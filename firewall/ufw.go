package firewall

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"firewall-manager/model"
	"firewall-manager/utils"
	"fmt"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	UFWRulesFile = "ufw_rules.json"

	actionMap = map[string]string{
		"ACCEPT": "allow",
		"ALLOW":  "allow",
		"DROP":   "deny",
		"DENY":   "deny",
		"REJECT": "deny",
	}
)

type UFWManager struct {
	rules []model.Rule
	sync.RWMutex
}

// 检查ufw是否可用
func UFWAvailable() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

func NewUFWManager() (*UFWManager, error) {
	m := &UFWManager{}
	if err := m.LoadRules(); err != nil {
		return nil, err
	}
	// 启动时自动恢复 JSON 中的规则
	if err := m.AutoRestoreRules(); err != nil {
		zap.L().Warn("[ufw] 启动时规则恢复失败", zap.Error(err))
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
var ufwRuleRegex = regexp.MustCompile(`^\s*\[\s*\d+\]\s+([^\s]+)\s+ALLOW IN\s+([^\s]+)`)

func (m *UFWManager) LoadRules() error {
	output, err := execCommand("ufw status numbered")
	if err != nil {
		return err
	}

	rules := []model.Rule{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if matches := ufwRuleRegex.FindStringSubmatch(line); len(matches) > 0 {
			port, err := strconv.Atoi(matches[1])
			if err != nil {
				zap.L().Error("[ufw] 解析端口失败", zap.String("line", line))
				continue
			}
			source := matches[4]
			if source == "Anywhere" {
				source = "0.0.0.0/0"
			}
			rules = append(rules, model.Rule{
				Port:      port,
				Protocol:  matches[2],
				Action:    strings.ToUpper(matches[3]),
				Chain:     "INPUT",
				SourceIPs: []string{source},
			})
		}
	}
	m.Lock()
	m.rules = rules
	m.Unlock()

	zap.L().Info("[ufw] 规则已加载", zap.Any("rules", rules))
	return nil
}

// AutoRestoreRules 启动时自动恢复 JSON 文件中的规则
func (m *UFWManager) AutoRestoreRules() error {
	m.Lock()
	defer m.Unlock()
	if _, err := os.Stat(UFWRulesFile); os.IsNotExist(err) {
		fmt.Println("[ufw] 未找到规则文件，跳过恢复")
		return nil
	}

	data, err := os.ReadFile(UFWRulesFile)
	if err != nil {
		return err
	}

	var savedRules []model.Rule
	if err = json.Unmarshal(data, &savedRules); err != nil {
		return err
	}

	// 加载当前系统规则，避免重复添加
	currentRules, err := m.ListRule(context.Background())
	if err != nil {
		return err
	}

	for _, r := range savedRules {
		if !ruleExists(r, currentRules) {
			zap.L().Info("[ufw] 恢复规则", zap.Int("port", r.Port),
				zap.String("protocol", r.Protocol), zap.Strings("src", r.SourceIPs))

			// 构造 RuleRequest 并添加
			req := model.RuleRequest(r)
			if err = m.AddRule(context.Background(), req); err != nil {
				zap.L().Error("[ufw] 恢复规则失败", zap.Error(err))
			}
			m.rules = append(m.rules, r)
		}
	}

	fmt.Println("[ufw] 规则恢复完成")
	return nil
}

func (m *UFWManager) ListRule(ctx context.Context) ([]model.Rule, error) {
	zap.L().Info("[ufw] 查看所有规则",
		zap.String("ip", utils.GetIP(ctx)),
		zap.Any("rules", m.rules))
	return append([]model.Rule{}, m.rules...), nil // 返回副本防止数据竞争
}

func (m *UFWManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	action, ok := actionMap[strings.ToUpper(req.Action)]
	if !ok {
		return fmt.Errorf("不支持的动作: %s", req.Action)
	}

	chain := strings.ToUpper(req.Chain)
	if chain == "" {
		chain = "INPUT" // 默认 INPUT
	}

	sourceIPs := req.SourceIPs
	if len(sourceIPs) == 0 {
		sourceIPs = []string{"any"}
	}
	addedIPs := make([]string, 0, len(sourceIPs))
	for _, ip := range sourceIPs {
		singleRule := req
		singleRule.SourceIPs = []string{ip}
		var cmd string
		switch chain {
		case "INPUT":
			cmd = fmt.Sprintf("ufw %s from %s to any port %d proto %s",
				action, ip, req.Port, req.Protocol)
		case "OUTPUT":
			cmd = fmt.Sprintf("ufw %s out to %s port %d proto %s",
				action, ip, req.Port, req.Protocol)
		default:
			return fmt.Errorf("UFW 不支持的链: %s", chain)
		}
		if out, err := execCommand(cmd); err != nil {
			zap.L().Error("[ufw] 添加规则失败", zap.String("cmd", cmd), zap.String("output", out))
			return err
		}
		zap.L().Info("[ufw] 添加规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", singleRule))
		addedIPs = append(addedIPs, ip)
	}
	m.rules = append(m.rules, model.Rule{
		Action:    strings.ToUpper(req.Action),
		Chain:     req.Chain,
		Port:      req.Port,
		Protocol:  req.Protocol,
		SourceIPs: addedIPs,
	})
	return m.saveRulesToFileUnlocked()
}

func (m *UFWManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	action, ok := actionMap[strings.ToUpper(req.Action)]
	if !ok {
		return fmt.Errorf("不支持的动作: %s", req.Action)
	}

	chain := strings.ToUpper(req.Chain)
	if chain == "" {
		chain = "INPUT" // 默认 INPUT
	}

	sourceIPs := req.SourceIPs
	if len(sourceIPs) == 0 {
		sourceIPs = []string{"any"}
	}
	deletedIPs := make([]string, 0, len(sourceIPs))
	for _, ip := range sourceIPs {
		singleRule := req
		singleRule.SourceIPs = []string{ip}
		var cmd string
		switch chain {
		case "INPUT":
			cmd = fmt.Sprintf("ufw delete %s from %s to any port %d proto %s",
				action, ip, req.Port, req.Protocol)
		case "OUTPUT":
			cmd = fmt.Sprintf("ufw delete %s out to %s port %d proto %s",
				action, ip, req.Port, req.Protocol)
		default:
			return fmt.Errorf("UFW 不支持的链: %s", chain)
		}
		if out, err := execCommand(cmd); err != nil {
			zap.L().Error("[ufw] 删除规则失败", zap.String("cmd", cmd), zap.String("output", out))
			return err
		}
		zap.L().Info("[ufw] 删除规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", singleRule))
		deletedIPs = append(deletedIPs, ip)
	}
	m.removeRuleFromCache(req, deletedIPs)
	return m.saveRulesToFileUnlocked()
}

func (m *UFWManager) removeRuleFromCache(req model.RuleRequest, ips []string) {
	updatedRules := make([]model.Rule, 0, len(m.rules))

	for _, r := range m.rules {
		if r.Port == req.Port &&
			strings.EqualFold(r.Protocol, req.Protocol) &&
			strings.EqualFold(r.Action, strings.ToUpper(req.Action)) {

			deletedIPs := RemoveAll(req.SourceIPs, ips)
			if len(deletedIPs) > 0 {
				r.SourceIPs = deletedIPs
				updatedRules = append(updatedRules, r)
			}
		} else {
			updatedRules = append(updatedRules, r)
		}
	}

	m.rules = updatedRules
}

func (m *UFWManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
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
	return m.LoadRules()
}

func (m *UFWManager) Type() string {
	return "ufw"
}

func (m *UFWManager) saveRulesToFileUnlocked() error {
	data, err := json.MarshalIndent(m.rules, "", "  ")
	if err != nil {
		zap.L().Error("Failed to marshal UFW rules")
		return err
	}
	return os.WriteFile(UFWRulesFile, data, 0644)
}

func ruleExists(r model.Rule, current []model.Rule) bool {
	for _, cr := range current {
		if r.Port == cr.Port && strings.EqualFold(r.Protocol, cr.Protocol) &&
			strings.EqualFold(r.Action, cr.Action) && sameStringSlice(r.SourceIPs, cr.SourceIPs) {
			return true
		}
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

func RemoveAll[T comparable](src, toRemove []T) []T {
	// 1. 把 toRemove 元素放进 map
	removeSet := make(map[T]struct{}, len(toRemove))
	for _, v := range toRemove {
		removeSet[v] = struct{}{}
	}

	// 2. 遍历 src，只保留不在 removeSet 的元素
	var result []T
	for _, v := range src {
		if _, found := removeSet[v]; !found {
			result = append(result, v)
		}
	}
	return result
}
