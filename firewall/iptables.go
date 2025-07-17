package firewall

import (
	"context"
	"encoding/json"
	"firewall-manager/model"
	"firewall-manager/utils"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const IptablesRulesFile = "iptables_rules.json"

type IptablesManager struct {
	ipt   *iptables.IPTables
	cache map[int][]model.Rule // key: action，例如 "ACCEPT"
	mu    sync.RWMutex
}

// TODO 保存配置文件/优雅关闭

func NewIptablesManager() (*IptablesManager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to init iptables: %v", err)
	}
	m := &IptablesManager{
		ipt:   ipt,
		cache: make(map[int][]model.Rule),
	}
	// 启动时加载本机现有规则
	if err := m.LoadCurrentRules(); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadCurrentRules 拉取系统现有规则到内存
func (m *IptablesManager) LoadCurrentRules() error {
	m.cache = make(map[int][]model.Rule) // 确保每次重新加载前清空
	// 1. 文件存在 → 直接读取 → 添加规则
	if _, err := os.Stat(IptablesRulesFile); err == nil {
		return m.Reload()
	}
	// 2. 文件不存在 → 从 iptables 获取并写入文件
	fmt.Println("[iptables] 规则文件不存在，正在从系统加载...")
	rules, err := m.GetRules()
	if err != nil {
		return err
	}

	for _, r := range rules {
		m.updateCacheAdd(r)
	}

	// 写入文件，避免下次重复加载
	if err := m.SaveRulesToFile(); err != nil {
		return err
	}

	fmt.Println("[iptables] 从系统加载规则并已保存到文件")
	return nil
	/*for _, chain := range chains {
		lines, err := m.ipt.List(m.inferTableByChain(chain), chain)
		if err != nil {
			// 添加错误日志记录具体原因
			zap.L().Warn("Failed to list chain",
				zap.String("table", m.inferTableByChain(chain)),
				zap.String("chain", chain),
				zap.Error(err))
			continue // 某些表/链可能不存在，跳过
		}
		var rules []model.Rule
		for _, line := range lines {
			if r := parseRuleLine(line); r != nil {
				rules = append(rules, *r)
			}
		}
		key := fmt.Sprintf("%s_%s", m.inferTableByChain(chain), chain)
		m.cache[key] = rules
	}

	fmt.Println("[iptables] 规则加载完成")
	return nil*/
}

// 检查iptables是否可用
func IPTAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func (m *IptablesManager) ListRule(ctx context.Context) ([]model.Rule, error) {
	allRules, err := m.GetRules()
	if err != nil {
		zap.L().Error("查看所有规则失败",
			zap.String("ip", utils.GetIP(ctx)),
			zap.Error(err))
		return nil, err
	}
	zap.L().Info("查看所有规则",
		zap.String("ip", utils.GetIP(ctx)),
		zap.Any("rules", allRules))
	return allRules, nil
}

func (m *IptablesManager) GetRules() ([]model.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. 执行 iptables-save 获取所有规则
	output, err := exec.Command("iptables-save").Output()
	if err != nil {
		return nil, err
	}

	var allRules []model.Rule
	lines := strings.Split(string(output), "\n")

	//var currentTable string

	// 2. 逐行解析
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释
		}

		//if strings.HasPrefix(line, "*") {
		//	// 表定义，如 *filter
		//	currentTable = strings.TrimPrefix(line, "*")
		//	continue
		//}

		//if strings.HasPrefix(line, ":") {
		//	// 链定义，如 :INPUT ACCEPT [0:0]
		//	parts := strings.Fields(line)
		//	if len(parts) >= 2 {
		//		chain := strings.TrimPrefix(parts[0], ":")
		//		policy := parts[1] // ACCEPT / DROP / ...
		//		allRules = append(allRules, model.Rule{
		//			Chain:  currentTable + ":" + chain,
		//			Action: policy,
		//		})
		//	}
		//	continue
		//}

		if strings.HasPrefix(line, "-A") {
			// 规则，如 -A INPUT -s 192.168.1.1/32 -p tcp --dport 80 -j ACCEPT
			if r := parseRuleLine(line); r != nil {
				allRules = append(allRules, model.Rule{
					Port:      r.Port,
					Protocol:  r.Protocol,
					Action:    r.Action,
					Chain:     r.Chain,
					SourceIPs: r.SourceIPs,
				})
			}
			continue
		}

		//if line == "COMMIT" {
		//	currentTable = ""
		//}
	}
	return allRules, nil
}

/*func (m *IptablesManager) ListRule(ctx context.Context) ([]model.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var allRules []model.Rule
	for _, chain := range chains {
		lines, err := m.ipt.List(m.inferTableByChain(chain), chain)
		if err != nil {
			zap.L().Warn("Failed to get chain policy",
				zap.String("ip", utils.GetIP(ctx)),
				zap.String("table", m.inferTableByChain(chain)),
				zap.String("chain", chain),
				zap.Error(err))
			continue // 某些表或链不存在就跳过
		}
		for _, line := range lines {
			if r := parseRuleLine(line); r != nil {
				rule := model.Rule{
					Port:      r.Port,
					Protocol:  r.Protocol,
					Action:    r.Action,
					Chain:     m.inferTableByChain(r.Chain) + ":" + r.Chain,
					SourceIPs: r.SourceIPs,
				}
				allRules = append(allRules, rule)
			}
		}
	}
	zap.L().Info("查看规则列表", zap.String("ip", utils.GetIP(ctx)), zap.Any("rules", allRules))
	return allRules, nil
}*/

func (m *IptablesManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r := model.Rule(req)

	/*// 如果 SourceIPs 为空，表示不指定来源地址，直接构造一条规则
	if len(req.SourceIPs) == 0 {
		if err := m.ipt.AppendUnique(m.inferTableByChain(req.Chain), req.Chain, buildArgsFromRule(r)...); err != nil {
			zap.L().Error("添加规则失败", zap.String("ip", utils.GetIP(ctx)), zap.Error(err))
			return err
		}
		m.updateCacheAdd(r)
		zap.L().Info("添加规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", r))
		return nil
	}*/

	for _, sourceIp := range req.SourceIPs {
		singleRule := r
		singleRule.SourceIPs = []string{sourceIp}
		if err := m.ipt.AppendUnique(m.inferTableByChain(req.Chain), req.Chain, buildArgsFromRule(singleRule)...); err != nil {
			zap.L().Error("添加规则失败", zap.String("ip", utils.GetIP(ctx)), zap.Error(err))
			return err
		}
		m.updateCacheAdd(r)
		zap.L().Info("添加规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", singleRule))
	}

	return nil
}

func (m *IptablesManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r := model.Rule(req)

	/*// 如果 SourceIPs 为空，表示不指定来源地址，直接构造一条规则
	if len(req.SourceIPs) == 0 {
		if err := m.ipt.Delete(m.inferTableByChain(req.Chain), req.Chain, buildArgsFromRule(r)...); err != nil {
			zap.L().Error("删除规则失败", zap.String("ip", utils.GetIP(ctx)), zap.Error(err))
			return err
		}
		m.updateCacheDelete(r)
		zap.L().Info("添加规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", r))
		return nil
	}*/

	for _, sourceIp := range req.SourceIPs {
		singleRule := r
		singleRule.SourceIPs = []string{sourceIp}
		if err := m.ipt.Delete(m.inferTableByChain(req.Chain), req.Chain, buildArgsFromRule(r)...); err != nil {
			zap.L().Error("删除规则失败", zap.String("ip", utils.GetIP(ctx)), zap.Error(err))
			return err
		}
		m.updateCacheDelete(r)
		zap.L().Info("删除规则成功", zap.String("ip", utils.GetIP(ctx)), zap.Any("rule", r))
	}
	return nil
}

func (m *IptablesManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	// 删除旧规则（即使不存在也忽略错误）
	_ = m.DeleteRule(ctx, edit.Old)
	// 添加新规则
	return m.AddRule(ctx, edit.New)
}

func (m *IptablesManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache = make(map[int][]model.Rule) // 确保每次重新加载前清空

	data, err := os.ReadFile(IptablesRulesFile)
	if err != nil {
		return err
	}

	var rules []model.Rule
	if err = json.Unmarshal(data, &rules); err != nil {
		zap.L().Error("解析规则文件失败", zap.Error(err))
		return err
	}

	for _, r := range rules {
		// 生成 iptables 参数
		args := buildArgsFromRule(r)

		exists, err := m.ipt.Exists(m.inferTableByChain(r.Chain), r.Chain, args...)
		if err != nil {
			return err
		}

		if !exists {
			err = m.ipt.Append(m.inferTableByChain(r.Chain), r.Chain, args...)
			if err != nil {
				zap.L().Error("恢复规则失败", zap.Any("rule", r), zap.Error(err))
				continue
			}
			zap.L().Info("恢复规则成功", zap.Any("rule", r))
		}

		// 更新缓存
		m.updateCacheAdd(r)

	}
	fmt.Println("配置规则恢复成功")
	return nil
}

func (m *IptablesManager) SaveRulesToFile() error {
	var allRules []model.Rule
	for _, rules := range m.cache {
		allRules = append(allRules, rules...)
	}

	data, err := json.MarshalIndent(allRules, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(IptablesRulesFile, data, 0644)
}

func buildArgsFromRule(rule model.Rule) []string {
	args := []string{}

	// IP 源地址
	for _, ip := range rule.SourceIPs {
		args = append(args, "-s", ip)
	}

	if rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)
		switch rule.Protocol {
		case "icmp":
			args = append(args, "-m", "icmp")
			args = append(args, "--icmp-type", "any") // 默认匹配所有 ICMP
		default:
			args = append(args, "-m", rule.Protocol)
			if rule.Port > 0 {
				args = append(args, "--dport", strconv.Itoa(rule.Port))
			}
		}
	}

	args = append(args, "-j", rule.Action)

	if rule.Action == "CHECKSUM" {
		args = append(args, "--checksum-fill")
	}

	return args
}

func (m *IptablesManager) Type() string {
	return "iptables"
}

func (m *IptablesManager) updateCacheAdd(r model.Rule) {
	m.cache[r.Port] = append(m.cache[r.Port], r)
}

func (m *IptablesManager) updateCacheDelete(r model.Rule) {
	if rules, ok := m.cache[r.Port]; ok {
		var newRules []model.Rule
		for _, rule := range rules {
			if !(ruleEqual(rule, r)) {
				newRules = append(newRules, rule)
			}
		}
		m.cache[r.Port] = newRules
	}
}

func ruleEqual(a, b model.Rule) bool {
	return a.Chain == b.Chain &&
		a.Protocol == b.Protocol &&
		a.Port == b.Port &&
		a.Action == b.Action &&
		strings.Join(a.SourceIPs, ",") == strings.Join(b.SourceIPs, ",")
}

func parseRuleLine(line string) *model.Rule {
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return nil
	}
	var r model.Rule
	var srcIPs []string

	for i := 0; i < len(tokens); i++ {
		if i+1 >= len(tokens) {
			continue
		}
		switch tokens[i] {
		case "-A":
			r.Chain = tokens[i+1]
		case "-s":
			srcIPs = append(srcIPs, tokens[i+1])
		case "-p":
			r.Protocol = tokens[i+1]
		case "--dport":
			if port, err := strconv.Atoi(tokens[i+1]); err == nil {
				r.Port = port
			}
		case "-j":
			r.Action = tokens[i+1]
		}
	}
	r.SourceIPs = srcIPs
	if r.Port == 0 && r.Protocol == "" {
		// 这类无效规则直接过滤
		return nil
	}
	if r.Chain == "" || r.Action == "" {
		return nil
	}
	if r.Action == "CHECKSUM" && r.Chain == "POSTROUTING" && r.Protocol == "udp" && r.Port == 68 {
		zap.L().Warn("跳过系统自动生成的 CHECKSUM DHCP 规则", zap.Any("rule", r))
		return nil
	}
	return &r
}

// 链到表的映射
func (m *IptablesManager) inferTableByChain(chain string) string {
	switch strings.ToUpper(chain) {
	case "PREROUTING", "POSTROUTING", "OUTPUT":
		return "nat" // 大多数情况下
	case "INPUT", "FORWARD":
		return "filter"
	default:
		// 检查自定义链
		//if custom, ok := m.customChains[chain]; ok {
		//	return custom.Table
		//}
		return "filter" // 默认
	}
}
