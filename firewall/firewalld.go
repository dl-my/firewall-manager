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
	"golang.org/x/sync/errgroup"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type FWManager struct {
	cache map[int][]model.FWRule
	index map[string]struct{}
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

func NewFWManager() (*FWManager, error) {
	m := &FWManager{
		cache: make(map[int][]model.FWRule),
		index: make(map[string]struct{}),
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

	m.cache = make(map[int][]model.FWRule) // 确保每次重新加载前清空
	m.index = make(map[string]struct{})

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
			m.cache[r.Rule.Port] = append(m.cache[r.Rule.Port], r)
			m.index[utils.IndexKey(r.Rule)] = struct{}{}
		}
	}
	logs.Info("[firewalld] 规则已加载", zap.Any("rules", m.cacheToRules()))
	return nil
}

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

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(5) // 控制并发数

	// 加载当前系统规则，避免重复添加
	for _, r := range savedRules {
		rule := r
		if m.ruleExists(rule) {
			continue
		}
		g.Go(func() error {
			return m.AddRule(ctx, model.RuleRequest(rule))
		})
	}
	if err := g.Wait(); err != nil {
		logs.Warn("[firewalld] 恢复规则部分失败", zap.Error(err))
	}
	logs.Info("[firewalld] 规则恢复完成")
	return nil
}

func (m *FWManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	rule := model.Rule(req)

	var addedRules []model.FWRule

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			logs.ErrorCtx(ctx, "[firewalld] 添加规则失败，无效的IP地址",
				zap.Any("rule", singleRule))
			return fmt.Errorf("[firewalld] 添加规则失败，无效的IP地址: %s", ip)
		}

		if m.ruleExists(singleRule) {
			continue
		}
		var fwType string
		if service := strings.ToLower(utils.GetServiceByPort(singleRule.Port, singleRule.Protocol)); service != "" {
			fwType = common.SERVICE
			if err := runFirewallCmd("--add-service", service, common.PERMANENT); err != nil {
				logs.ErrorCtx(ctx, "[firewalld] 添加服务规则失败",
					zap.Any("rule", singleRule),
					zap.String("规则类型", fwType),
					zap.Error(err))
				return err
			}
		} else {
			fwType = common.RICHRULE
			if err := runFirewallCmd("--add-rich-rule", buildRichRuleString(singleRule), common.PERMANENT); err != nil {
				logs.ErrorCtx(ctx, "[firewalld] 添加规则失败",
					zap.Any("rule", singleRule),
					zap.String("规则类型", fwType),
					zap.Error(err))
				return err
			}
		}

		addedRules = append(addedRules, model.FWRule{Rule: singleRule, Type: fwType})
		m.index[utils.IndexKey(singleRule)] = struct{}{}
		logs.InfoCtx(ctx, "[firewalld] 添加规则成功",
			zap.Any("rule", singleRule),
			zap.String("规则类型", fwType))
	}

	if len(addedRules) > 0 {
		if err := runFirewallCmd("--reload"); err != nil {
			return err
		}
		m.cache[rule.Port] = append(m.cache[rule.Port], addedRules...)
	}
	return nil
	//return m.saveRulesToFileUnlocked()
}

func (m *FWManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	m.Lock()
	defer m.Unlock()

	rule := model.Rule(req)

	var deletedRules []model.FWRule

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			logs.ErrorCtx(ctx, "[firewalld] 删除规则失败，无效的IP地址",
				zap.Any("rule", singleRule))
			return fmt.Errorf("[firewalld] 删除规则失败，无效的IP地址: %s", ip)
		}

		fwType := m.getRuleType(singleRule)

		if !m.ruleExists(singleRule) || fwType == "" {
			continue
		}

		var cmdErr error
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

		if cmdErr != nil {
			return cmdErr
		}

		deletedRules = append(deletedRules, model.FWRule{Rule: singleRule, Type: fwType})
		logs.InfoCtx(ctx, "[firewalld] 删除规则成功",
			zap.Any("rule", singleRule),
			zap.String("规则类型", fwType))
	}

	if err := runFirewallCmd("--reload"); err != nil {
		return err
	}
	m.removeRuleFromCache(deletedRules)
	return nil
	//return m.saveRulesToFileUnlocked()
}

func (m *FWManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	rule := model.Rule(edit.Old)
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		if !m.ruleExists(singleRule) {
			return fmt.Errorf("[firewalld] 编辑的规则不存在: %+v", singleRule)
		}
	}
	if err := m.DeleteRule(ctx, edit.Old); err != nil {
		return err
	}
	return m.AddRule(ctx, edit.New)
}

func (m *FWManager) ListRule() []model.Rule {
	rules := m.cacheToRules()
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
	if err := m.saveRulesToFileUnlocked(); err != nil {
		logs.Error("[firewalld] 保存规则失败", zap.Error(err))
		return err
	}
	return nil
}

func (m *FWManager) saveRulesToFileUnlocked() error {
	rules := m.cacheToRules()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(common.FWRulesFile, data, 0644)
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

func (m *FWManager) removeRuleFromCache(rules []model.FWRule) {
	for _, r := range rules {
		port := r.Rule.Port
		if cachedRules, ok := m.cache[port]; ok {
			newRules := make([]model.FWRule, 0, len(cachedRules))

			for _, cr := range cachedRules {
				// 判断是否为要删除的规则（port, protocol, action, chain, source_ips 都匹配）
				if !utils.IsSameRule(r.Rule, cr.Rule) {
					newRules = append(newRules, cr)
				} else {
					delete(m.index, utils.IndexKey(cr.Rule))
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

func (m *FWManager) cacheToRules() []model.Rule {
	// key: "port|protocol|action|chain"
	merged := make(map[string]model.Rule)

	for _, rules := range m.cache {
		for _, r := range rules {
			key := fmt.Sprintf("%d|%s|%s|%s", r.Rule.Port, r.Rule.Protocol, r.Rule.Action, r.Rule.Chain)

			if existing, ok := merged[key]; ok {
				// 合并 source_ips
				existing.SourceIPs = append(existing.SourceIPs, r.Rule.SourceIPs...)
				merged[key] = existing
			} else {
				merged[key] = r.Rule
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

func (m *FWManager) ruleExists(r model.Rule) bool {
	_, ok := m.index[utils.IndexKey(r)]
	return ok
}

// 获取缓存中对应规则的Type
func (m *FWManager) getRuleType(r model.Rule) string {
	if rules, ok := m.cache[r.Port]; ok {
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
