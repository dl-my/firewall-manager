package firewall

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"firewall-manager/common/common"
	"firewall-manager/common/utils"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type UFWManager struct {
	cache map[int][]model.Rule
	sync.RWMutex
}

// 检查ufw是否可用
func UFWAvailable() bool {
	if _, err := exec.LookPath("ufw"); err != nil {
		return false // 程序不存在
	}
	cmd := exec.Command("ufw", "status")
	cmd.Env = append(os.Environ(), "LANG=C") // 强制英文输出

	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// "Status: active" 表示已启用
	return strings.Contains(string(out), "Status: active")
}

func NewUFWManager() (*UFWManager, error) {
	m := &UFWManager{
		cache: make(map[int][]model.Rule),
	}
	if err := m.LoadRules(); err != nil {
		return nil, err
	}
	// 启动时自动恢复 JSON 中的规则
	if err := m.AutoRestoreRules(); err != nil {
		zap.L().Error("[ufw] 启动时规则恢复失败", zap.Error(err))
	}
	return m, nil
}

// 执行系统命令
func execCommand(cmdStr string) (string, error) {
	cmd := exec.Command("bash", "-c", cmdStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// 正则表达式以匹配UFW输出格式
var ufwV4Regex = regexp.MustCompile(`^\s*\[\s*(\d+)\]\s+(.+?)\s+([A-Z]+)\s+([A-Z]+)\s+((?:Anywhere\s*)|(?:[\d\.]+(?:/\d+)?))\s*$`)
var portProtoRegex = regexp.MustCompile(`^(\d+)(?:/([a-z]+))?$`)

func (m *UFWManager) LoadRules() error {
	m.Lock()
	defer m.Unlock()

	m.cache = make(map[int][]model.Rule) // 确保每次重新加载前清空

	output, err := execCommand("ufw status numbered")
	if err != nil {
		return err
	}

	var rules []model.Rule
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if matches := ufwV4Regex.FindStringSubmatch(line); len(matches) >= 6 {
			service := matches[2]
			action := common.UFWActionMap[strings.ToUpper(matches[3])]
			chain := common.UFWChainMap[strings.ToUpper(matches[4])]
			source := matches[5]
			if strings.TrimSpace(source) == "Anywhere" {
				source = "0.0.0.0/0"
			}
			port, protocol := extractPortAndProtocol(service)
			r := model.Rule{
				Port:      port,
				Protocol:  protocol,
				Action:    action,
				Chain:     chain,
				SourceIPs: []string{source},
			}
			m.cache[r.Port] = append(m.cache[r.Port], r)
			rules = append(rules, r)
		}
	}
	zap.L().Info("[ufw] 规则已加载", zap.Any("rules", rules))
	return nil
}

func extractPortAndProtocol(service string) (int, string) {
	if port, exists := common.ServiceToPortMap[strings.ToUpper(service)]; exists {
		service = port
	}
	// 处理标准格式 "端口/协议"
	if matches := portProtoRegex.FindStringSubmatch(service); len(matches) > 0 {
		port, err := strconv.Atoi(matches[1])
		if err != nil {
			zap.L().Warn("解析服务端口失败", zap.String("service", service))
			return 0, ""
		}

		protocol := matches[2]
		if protocol == "" {
			protocol = "tcp" // 默认使用TCP
		}

		return port, protocol
	}

	// 处理特殊情况 (如 mDNS, 多播地址等)
	if strings.Contains(service, "mDNS") {
		return 5353, "udp"
	}

	// 无法解析端口，返回0
	zap.L().Warn("[ufw] 无法解析端口", zap.String("service", service))
	return 0, ""
}

// AutoRestoreRules 启动时自动恢复 JSON 文件中的规则
func (m *UFWManager) AutoRestoreRules() error {
	if _, err := os.Stat(common.UFWRulesFile); os.IsNotExist(err) {
		fmt.Println("[ufw] 未找到规则文件，跳过恢复")
		return nil
	}

	data, err := os.ReadFile(common.UFWRulesFile)
	if err != nil {
		return err
	}

	var savedRules []model.Rule
	if err = json.Unmarshal(data, &savedRules); err != nil {
		return err
	}

	// 加载当前系统规则，避免重复添加
	for _, r := range savedRules {
		if !ruleExists(r, m.cache) {
			// 构造 RuleRequest 并添加
			req := model.RuleRequest(r)
			if err = m.AddRule(context.Background(), req); err != nil {
				zap.L().Error("[ufw] 恢复规则失败", zap.Error(err))
			}
		}
	}

	fmt.Println("[ufw] 规则恢复完成")
	return nil
}

func (m *UFWManager) ListRule(ctx context.Context) ([]model.Rule, error) {
	rules := m.cacheToRules()

	zap.L().Info("[ufw] 查看所有规则",
		zap.String("ip", utils.GetIP(ctx)),
		zap.Any("rules", rules))
	return rules, nil
}

func (m *UFWManager) cacheToRules() []model.Rule {
	// key: "port|protocol|action|chain"
	merged := make(map[string]model.Rule)

	for _, rules := range m.cache {
		for _, r := range rules {
			key := fmt.Sprintf("%d|%s|%s|%s", r.Port, r.Protocol, r.Action, r.Chain)

			if existing, ok := merged[key]; ok {
				// 合并 source_ips
				existing.SourceIPs = append(existing.SourceIPs, r.SourceIPs...)
				merged[key] = existing
			} else {
				merged[key] = r
			}
		}
	}

	// 转回数组
	result := make([]model.Rule, 0, len(merged))
	for _, r := range merged {
		result = append(result, r)
	}
	return result
}

func (m *UFWManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	rule, err := requestToRule(req)
	if err != nil {
		zap.L().Error("[ufw] 转换规则失败", zap.Error(err))
		return err
	}

	action := strings.ToLower(rule.Action)
	var addedRules []model.Rule // 记录成功添加的规则

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		var cmd string
		switch rule.Chain {
		case "INPUT":
			cmd = fmt.Sprintf("ufw %s from %s to any port %d proto %s",
				action, ip, singleRule.Port, singleRule.Protocol)
		case "OUTPUT":
			cmd = fmt.Sprintf("ufw %s out to %s port %d proto %s",
				action, ip, singleRule.Port, singleRule.Protocol)
		default:
			return fmt.Errorf("UFW 不支持的链: %s", singleRule.Chain)
		}

		if out, err := execCommand(cmd); err != nil {
			zap.L().Error("[ufw] 添加规则失败",
				zap.String("cmd", cmd),
				zap.String("output", out),
				zap.Error(err))
			return err
		}

		if !ruleExists(singleRule, m.cache) {
			zap.L().Info("[ufw] 添加规则成功",
				zap.String("ip", utils.GetIP(ctx)),
				zap.Any("rule", singleRule))
			addedRules = append(addedRules, singleRule)
		}
	}

	m.cache[rule.Port] = append(m.cache[rule.Port], addedRules...)
	return m.saveRulesToFileUnlocked()
}

// TODO 系统自带规则以服务命名而非端口,需做特殊判断
func (m *UFWManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	rule, err := requestToRule(req)
	if err != nil {
		zap.L().Error("[ufw] 转换规则失败", zap.Error(err))
		return err
	}

	action := strings.ToLower(rule.Action)
	var deletedRules []model.Rule // 记录成功添加的规则

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		var cmd string
		switch rule.Chain {
		case "INPUT":
			cmd = fmt.Sprintf("ufw delete %s from %s to any port %d proto %s",
				action, ip, singleRule.Port, singleRule.Protocol)
		case "OUTPUT":
			cmd = fmt.Sprintf("ufw delete %s out to %s port %d proto %s",
				action, ip, singleRule.Port, singleRule.Protocol)
		default:
			return fmt.Errorf("UFW 不支持的链: %s", singleRule.Chain)
		}

		if out, err := execCommand(cmd); err != nil {
			zap.L().Error("[ufw] 删除规则失败",
				zap.String("cmd", cmd),
				zap.String("output", out),
				zap.Error(err))
			return err
		}

		if ruleExists(singleRule, m.cache) {
			zap.L().Info("[ufw] 删除规则成功",
				zap.String("ip", utils.GetIP(ctx)),
				zap.Any("rule", singleRule))
			deletedRules = append(deletedRules, singleRule)
		}

	}

	m.removeRuleFromCache(deletedRules)
	return m.saveRulesToFileUnlocked()
}

func (m *UFWManager) removeRuleFromCache(rules []model.Rule) {
	for _, r := range rules {
		port := r.Port
		if cachedRules, ok := m.cache[port]; ok {
			newRules := make([]model.Rule, 0, len(cachedRules))

			for _, cr := range cachedRules {
				// 判断是否为要删除的规则（port, protocol, action, chain, source_ips 都匹配）
				if !isSameRule(cr, r) {
					newRules = append(newRules, cr)
				}
			}

			// 如果删空了，直接删除这个 key
			if len(newRules) == 0 {
				delete(m.cache, port)
			} else {
				m.cache[port] = newRules
			}
		}
	}
}

func (m *UFWManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	rule, err := requestToRule(edit.Old)
	if err != nil {
		zap.L().Error("[ufw] 转换规则失败", zap.Error(err))
		return err
	}
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		if !ruleExists(singleRule, m.cache) {
			return fmt.Errorf("编辑的规则不存在")
		}
	}
	if err := m.DeleteRule(ctx, edit.Old); err != nil {
		return err
	}
	return m.AddRule(ctx, edit.New)
}

func (m *UFWManager) Reload() error {
	fmt.Println("[ufw] 重载中")
	out, err := exec.Command("ufw", "reload").CombinedOutput()
	if err != nil {
		zap.L().Error("[ufw] 重载失败: ", zap.Error(err), zap.String("输出", string(out)))
		return err
	}
	// 重载系统配置及自定义规则
	//err = m.LoadRules()
	//if err != nil {
	//	zap.L().Error("[ufw] 重载失败: ", zap.Error(err))
	//	return err
	//}
	//return m.AutoRestoreRules()
	return m.LoadRules()
}

func (m *UFWManager) Type() string {
	return "ufw"
}

func (m *UFWManager) saveRulesToFileUnlocked() error {
	rules := m.cacheToRules()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		zap.L().Error("Failed to marshal UFW rules")
		return err
	}
	return os.WriteFile(common.UFWRulesFile, data, 0644)
}

func ruleExists(r model.Rule, current map[int][]model.Rule) bool {
	if rules, ok := current[r.Port]; ok {
		for _, rule := range rules {
			if isSameRule(r, rule) {
				return true
			}
		}
	}
	return false
}

func isSameRule(a, b model.Rule) bool {
	if a.Port == b.Port && strings.EqualFold(a.Protocol, b.Protocol) &&
		strings.EqualFold(a.Action, b.Action) && sameStringSlice(a.SourceIPs, b.SourceIPs) {
		return true
	}
	return false
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func requestToRule(req model.RuleRequest) (model.Rule, error) {
	action, ok := common.UFWActionMap[strings.ToUpper(req.Action)]
	if !ok {
		return model.Rule{}, fmt.Errorf("不支持的动作: %s", req.Action)
	}
	chain, ok := common.UFWChainMap[strings.ToUpper(req.Chain)]
	if !ok {
		return model.Rule{}, fmt.Errorf("不支持的链: %s", req.Chain)
	}
	sourceIPs := req.SourceIPs
	if len(sourceIPs) == 0 {
		sourceIPs = []string{"any"}
	}
	return model.Rule{
		Action:    action,
		Chain:     chain,
		Port:      req.Port,
		Protocol:  strings.ToLower(req.Protocol),
		SourceIPs: sourceIPs,
	}, nil
}
