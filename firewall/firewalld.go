package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"firewall-manager/common/common"
	"firewall-manager/common/logs"
	"firewall-manager/common/utils"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type FWManager struct {
	cache *RuleCache[model.FWRule]
	sync.RWMutex
}

// FWAvailable 检查firewalld是否可用
func FWAvailable() bool {
	// 1. 检查是否安装
	if _, err := exec.LookPath(common.FWCMD); err != nil {
		return false
	}

	// 2. 检查是否正在运行
	cmd := exec.Command(common.FWCMD, "--state")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return false
	}

	return strings.TrimSpace(out.String()) == "running"
}

// NewFWManager 初始化 Firewalld 管理器
func NewFWManager() (*FWManager, error) {
	m := &FWManager{
		cache: NewRuleCache[model.FWRule](),
	}
	if err := m.loadRules(); err != nil {
		logs.Error("[firewalld] 加载规则失败", zap.Error(err))
		return nil, err
	}
	// 启动时自动恢复 JSON 中的规则
	//if err := m.autoRestoreRules(); err != nil {
	//	logs.Error("[firewalld] 启动时规则恢复失败", zap.Error(err))
	//}
	return m, nil
}

func (m *FWManager) loadRules() error {
	m.Lock()
	defer m.Unlock()

	m.cache = NewRuleCache[model.FWRule]() // 确保每次重新加载前清空

	loaders := []func() ([]model.FWRule, error){
		m.loadPort, m.loadService, m.loadRichRule,
	}
	for _, loader := range loaders {
		rules, err := loader()
		if err != nil {
			logs.Error("[firewalld] 加载规则失败", zap.Error(err))
			return err
		}
		for _, r := range rules {
			m.cache.Add(r, utils.IndexKey(r.Rule))
		}
	}
	logs.Info("[firewalld] 规则已加载", zap.Any("rules", m.cache.ToRules()))
	return nil
}

// TODO
func (m *FWManager) autoRestoreRules() error {
	if _, err := os.Stat(common.FWRulesFile); os.IsNotExist(err) {
		logs.Warn("[firewalld] 未找到规则文件，跳过恢复")
		return nil
	}

	data, err := os.ReadFile(common.FWRulesFile)
	if err != nil {
		return err
	}

	var savedRules []model.Rule
	if err = json.Unmarshal(data, &savedRules); err != nil {
		return err
	}

	// 加载当前系统规则，避免重复添加
	for _, r := range savedRules {
		if !m.cache.Exists(utils.IndexKey(r)) {
			// 构造 RuleRequest 并添加
			req := model.RuleRequest(r)
			if err = m.AddRule(context.Background(), req); err != nil {
				logs.Warn("[firewalld] 恢复规则失败", zap.Error(err))
			}
		}
	}
	logs.Info("[firewalld] 规则恢复完成")
	return nil
}

func (m *FWManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Add)
}

func (m *FWManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Delete)
}

func (m *FWManager) applyRules(ctx context.Context, req model.RuleRequest, method string) error {
	rule := model.Rule(req)
	var processedRules []model.FWRule

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		var cmdErr error

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			return fmt.Errorf("[firewalld] 删除规则失败，无效的IP地址: %s", ip)
		}

		fwType := m.getRuleType(singleRule)
		key := utils.IndexKey(singleRule)
		exists := m.cache.Exists(key)

		if (method == common.Add && exists) || (method == common.Delete && !exists && fwType == "") {
			continue
		}

		if method == common.Add {
			// 判断规则类型并执行命令
			if service := strings.ToLower(utils.GetServiceByPort(rule.Port, rule.Protocol)); service != "" {
				fwType = common.SERVICE
				cmdErr = runFirewallCmd("--add-service", service, common.PERMANENT)
			} else {
				fwType = common.RICHRULE
				cmdErr = runFirewallCmd("--add-rich-rule", buildRichRuleString(singleRule), common.PERMANENT)
			}
		} else {
			switch fwType {
			case common.PORT:
				cmdErr = runFirewallCmd("--remove-port", fmt.Sprintf("%d/%s", singleRule.Port, singleRule.Protocol), common.PERMANENT)
			case common.SERVICE:
				service := strings.ToLower(utils.GetServiceByPort(singleRule.Port, singleRule.Protocol))
				cmdErr = runFirewallCmd("--remove-service", service, common.PERMANENT)
			case common.RICHRULE:
				cmdErr = runFirewallCmd("--remove-rich-rule", buildRichRuleString(singleRule), common.PERMANENT)
			default:
				cmdErr = fmt.Errorf("[firewalld] 不支持的规则类型: %s", fwType)
			}
		}

		if cmdErr != nil {
			return cmdErr
		}

		fwRule := model.FWRule{Rule: singleRule, Type: fwType}
		processedRules = append(processedRules, fwRule)
	}

	if len(processedRules) == 0 {
		return nil
	}

	// 修改缓存（只在需要时加锁）
	m.Lock()
	defer m.Unlock()
	if method == common.Add {
		for _, r := range processedRules {
			m.cache.Add(r, utils.IndexKey(r.Rule))
		}
	} else {
		m.cache.Remove(processedRules)
	}

	if err := runFirewallCmd("--reload"); err != nil {
		return err
	}

	logs.InfoCtx(ctx, fmt.Sprintf("[firewalld] %s规则成功", method), zap.Any("rules", processedRules))
	return nil
}

func (m *FWManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	return m.cache.EditRuleGeneric(ctx, edit, m.DeleteRule, m.AddRule, m.Type())
}

func (m *FWManager) ListRule() []model.Rule {
	rules := m.cache.ToRules()
	return rules
}

func (m *FWManager) Reload() error {
	zap.L().Debug("[firewalld] 开始重载")
	if err := runFirewallCmd("--reload"); err != nil {
		return err
	}
	// 重载系统配置及自定义规则
	//err = m.loadRules()
	//if err != nil {
	//	logs.Error("[firewalld] 重载失败: ", zap.Error(err))
	//	return err
	//}
	//return m.autoRestoreRules()
	return m.loadRules()
}

func (m *FWManager) Type() string {
	return "firewalld"
}

func (m *FWManager) SaveRules() error {
	m.RLock()
	defer m.RUnlock()
	if err := m.cache.saveRulesToFileUnlocked(common.FWRulesFile); err != nil {
		logs.Error("[firewalld] 保存规则失败", zap.Error(err))
		return err
	}
	return nil
}

func (m *FWManager) loadPort() ([]model.FWRule, error) {
	var rules []model.FWRule

	cmd := exec.Command(common.FWCMD, "--list-ports")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("[firewalld] 加载普通规则失败: %v, 输出: %s", err, string(output))
	}

	ports := strings.Fields(strings.TrimSpace(string(output)))
	for _, p := range ports {
		pp := strings.Split(p, "/")
		if len(pp) == 2 {
			port, _ := strconv.Atoi(pp[0])
			rule := model.FWRule{
				Rule: model.Rule{
					Port:      port,
					Protocol:  pp[1],
					Action:    "ACCEPT",
					Chain:     "INPUT",
					SourceIPs: []string{common.DefaultIP},
				},
				Type: common.PORT,
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (m *FWManager) loadService() ([]model.FWRule, error) {
	var rules []model.FWRule

	cmd := exec.Command(common.FWCMD, "--list-services")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("[firewalld] 加载服务规则失败: %v, 输出: %s", err, string(output))
	}

	service := strings.Fields(strings.TrimSpace(string(output)))
	for _, s := range service {
		port, protocol := utils.ExtractPortAndProtocol(s)
		rule := model.FWRule{
			Rule: model.Rule{
				Port:      port,
				Protocol:  protocol,
				Action:    "ACCEPT",
				Chain:     "INPUT",
				SourceIPs: []string{common.DefaultIP},
			},
			Type: common.SERVICE,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (m *FWManager) loadRichRule() ([]model.FWRule, error) {
	var rules []model.FWRule

	cmd := exec.Command(common.FWCMD, "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("[firewalld] 加载 rich rules 失败: %v, 输出: %s", err, string(output))
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if rule, ok := utils.RichRuleParse(line); ok {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// 获取缓存中对应规则的Type
func (m *FWManager) getRuleType(r model.Rule) string {
	if rules, ok := m.cache.cache[r.Port]; ok {
		for _, rule := range rules {
			if utils.IsSameRule(r, rule.Rule) {
				return rule.Type
			}
		}
	}
	return ""
}

func buildRichRuleString(rule model.Rule) string {
	parts := []string{fmt.Sprintf("rule family=\"%s\"", common.IPV4)}
	if len(rule.SourceIPs) == 0 {
		rule.SourceIPs = []string{common.DefaultIP}
	}
	// TODO: 添加其他字段的处理逻辑
	switch rule.Chain {
	case "OUTPUT":
		parts = append(parts, fmt.Sprintf("destination address=\"%s\"", rule.SourceIPs[0]))
	default:
		parts = append(parts, fmt.Sprintf("source address=\"%s\"", rule.SourceIPs[0]))
	}

	if rule.Port != 0 {
		parts = append(parts, fmt.Sprintf("port port=\"%d\" protocol=\"%s\"", rule.Port, rule.Protocol))
	}
	parts = append(parts, strings.ToLower(rule.Action))
	return strings.Join(parts, " ")
}

func runFirewallCmd(args ...string) error {
	cmd := exec.Command(common.FWCMD, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, stderr.String())
	}
	return nil
}
