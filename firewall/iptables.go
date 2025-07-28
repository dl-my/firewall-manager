package firewall

import (
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
	"strings"
	"sync"
)

type IptablesManager struct {
	cache map[int][]model.IptablesRule // key: port 例如 3306
	index map[string]string
	sync.RWMutex
}

func NewIptablesManager() (*IptablesManager, error) {
	m := &IptablesManager{
		cache: make(map[int][]model.IptablesRule),
		index: make(map[string]string),
	}
	// 启动时加载本机现有规则
	if err := m.loadRules(); err != nil {
		return nil, err
	}
	return m, nil
}

// IPTAvailable 检查iptables是否可用
func IPTAvailable() bool {
	_, err := exec.LookPath(common.IptablesPath)
	return err == nil
}

// LoadRules 拉取系统现有规则到内存
func (m *IptablesManager) loadRules() error {
	m.Lock()
	defer m.Unlock()

	m.cache = make(map[int][]model.IptablesRule) // 确保每次重新加载前清空
	m.index = make(map[string]string)

	lines, err := fetchSystemRules()
	if err != nil {
		return err
	}

	rules := utils.IptablesParseRules(lines)
	for _, r := range rules {
		m.addToCache(r)
	}

	logs.Info("[iptables] 规则已加载", zap.Any("rules", m.cacheToRules()))
	return nil
}

func (m *IptablesManager) autoRestoreRules() error {
	if _, err := os.Stat(common.IptablesRulesFile); os.IsNotExist(err) {
		logs.Info("[iptables] 未找到规则文件，跳过恢复")
		return nil
	}

	data, err := os.ReadFile(common.IptablesRulesFile)
	if err != nil {
		return err
	}

	var savedRules []model.IptablesRule
	var addedRules []model.IptablesRule
	var rulesBatch []string
	if err = json.Unmarshal(data, &savedRules); err != nil {
		return err
	}

	// 加载当前系统规则，避免重复添加
	for _, r := range savedRules {
		if m.ruleExists(r.Rule) {
			continue
		}
		rulesBatch = append(rulesBatch, r.Raw)
		addedRules = append(addedRules, r)
	}
	// 如果没有新规则需要添加，直接返回
	if len(rulesBatch) == 0 {
		return nil
	}

	if err := applyRulesWithIptablesRestore(rulesBatch); err != nil {
		logs.Warn("[iptables] 恢复规则失败", zap.Error(err))
		return err
	}

	// 更新缓存
	m.Lock()
	defer m.Unlock()
	for _, r := range addedRules {
		m.addToCache(r)
		logs.Info("[iptables] 恢复规则成功", zap.Any("rule", r.Rule))
	}
	logs.Info("[iptables] 规则恢复完成")
	return nil
}

func (m *IptablesManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	rule := model.Rule(req)
	var addedRules []model.IptablesRule
	var rulesBatch []string

	// 生成所有待添加的规则
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			logs.ErrorCtx(ctx, "[iptables] 添加规则失败，无效的IP地址",
				zap.Any("rule", singleRule))
			return fmt.Errorf("[iptables] 添加规则失败，无效的IP地址: %s", ip)
		}

		if m.ruleExists(singleRule) {
			continue
		}

		raw := buildIptablesRule(singleRule)
		rulesBatch = append(rulesBatch, raw)
		addedRules = append(addedRules, model.IptablesRule{Rule: singleRule, Raw: raw})
	}

	// 如果没有新规则需要添加，直接返回
	if len(rulesBatch) == 0 {
		return nil
	}

	if err := applyRulesWithIptablesRestore(rulesBatch); err != nil {
		logs.ErrorCtx(ctx, "[iptables] 批量添加规则失败", zap.Error(err))
		return err
	}

	// 更新缓存
	m.Lock()
	defer m.Unlock()
	for _, r := range addedRules {
		m.addToCache(r)
		logs.InfoCtx(ctx, "[iptables] 添加规则成功", zap.Any("rule", r.Rule))
	}

	return nil
}

func (m *IptablesManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	rule := model.Rule(req)
	var deletedRules []model.IptablesRule
	var deleteBatch []string

	// 找到所有需要删除的规则
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			logs.ErrorCtx(ctx, "[iptables] 删除规则失败，无效的IP地址",
				zap.Any("rule", singleRule))
			return fmt.Errorf("[iptables] 删除规则失败，无效的IP地址: %s", ip)
		}

		if !m.ruleExists(singleRule) {
			continue
		}

		raw := m.index[utils.IndexKey(singleRule)]
		deleteBatch = append(deleteBatch, strings.Replace(raw, "-A", "-D", 1))
		deletedRules = append(deletedRules, model.IptablesRule{Rule: singleRule, Raw: raw})
	}

	// 如果没有规则需要删除
	if len(deleteBatch) == 0 {
		return nil
	}

	// 使用 iptables-restore 批量删除
	if err := applyRulesWithIptablesRestore(deleteBatch); err != nil {
		logs.ErrorCtx(ctx, "[iptables] 批量删除规则失败", zap.Error(err))
		return err
	}

	// 从缓存中移除
	m.Lock()
	defer m.Unlock()
	m.removeRuleFromCache(deletedRules)

	// 日志
	for _, r := range deletedRules {
		logs.InfoCtx(ctx, "[iptables] 删除规则成功", zap.Any("rule", r.Rule))
	}

	return nil
}

func (m *IptablesManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	rule := model.Rule(edit.Old)
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		if !m.ruleExists(singleRule) {
			return fmt.Errorf("[iptables] 编辑规则不存在: %+v", singleRule)
		}
	}
	if err := m.DeleteRule(ctx, edit.Old); err != nil {
		return err
	}
	if err := m.AddRule(ctx, edit.New); err != nil {
		return err
	}
	logs.InfoCtx(ctx, "[iptables] 编辑规则",
		zap.Any("oldRule", edit.Old),
		zap.Any("newRule", edit.New))
	return nil
}

func (m *IptablesManager) ListRule() []model.Rule {
	allRules := m.cacheToRules()
	return allRules
}

func (m *IptablesManager) SaveRules() error {
	m.Lock()
	defer m.Unlock()
	if err := m.saveRulesToFileUnlocked(); err != nil {
		return err
	}
	logs.Info("[iptables] 规则保存成功",
		zap.String("iptables_file", "./rules.v4"),
		zap.String("json_file", common.IptablesRulesFile))
	return nil
}

func (m *IptablesManager) Type() string {
	return "iptables"
}

func (m *IptablesManager) Reload() error {
	cmd := exec.Command("iptables-restore", "./rules.v4")
	if out, err := cmd.CombinedOutput(); err != nil {
		logs.Error("[iptables] 重载失败", zap.Error(err), zap.String("output", string(out)))
		return err
	}
	return m.loadRules()
}

func (m *IptablesManager) addToCache(rule model.IptablesRule) {
	port := rule.Rule.Port
	m.cache[port] = append(m.cache[port], rule)
	m.index[utils.IndexKey(rule.Rule)] = rule.Raw
}

func (m *IptablesManager) removeRuleFromCache(rules []model.IptablesRule) {
	for _, r := range rules {
		port := r.Rule.Port
		if cachedRules, ok := m.cache[port]; ok {
			newRules := make([]model.IptablesRule, 0, len(cachedRules))

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

func (m *IptablesManager) cacheToRules() []model.Rule {
	merged := make(map[string]model.Rule)
	m.RLock()
	defer m.RUnlock()

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

func (m *IptablesManager) ruleExists(r model.Rule) bool {
	m.RLock()
	defer m.RUnlock()
	_, ok := m.index[utils.IndexKey(r)]
	return ok
}

func (m *IptablesManager) saveRulesToFileUnlocked() error {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		logs.Error("[iptables] 规则保存失败", zap.Error(err))
		return err
	}
	if err := os.WriteFile("./rules.v4", out, 0644); err != nil {
		return err
	}
	// 保存为json文件
	var rules []model.IptablesRule
	for _, rule := range m.cache {
		rules = append(rules, rule...)
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		logs.Error("[iptables] 规则序列化失败", zap.Error(err))
		return err
	}
	return os.WriteFile(common.IptablesRulesFile, data, 0644)
}

func fetchSystemRules() ([]string, error) {
	out, err := exec.Command("iptables", "-S").Output()
	if err != nil {
		return nil, fmt.Errorf("[iptables] 加载规则失败: %v", err)
	}
	return strings.Split(string(out), "\n"), nil
}

func buildIptablesRule(rule model.Rule) string {
	ipFlag := "-s"
	targetIP := rule.SourceIPs[0]
	if strings.ToUpper(rule.Chain) == "OUTPUT" {
		ipFlag = "-d"
	}
	return fmt.Sprintf("-A %s %s %s -p %s -m %s --dport %d -m conntrack --ctstate NEW,UNTRACKED -j %s",
		rule.Chain, ipFlag, targetIP, rule.Protocol, rule.Protocol, rule.Port, rule.Action)
}

// 批量执行 iptables-restore
func applyRulesWithIptablesRestore(rules []string) error {
	// 拼接符合 iptables-restore 格式的规则
	// 只修改 filter 表，如果有 nat 表也可扩展
	var builder strings.Builder
	builder.WriteString("*filter\n")
	for _, r := range rules {
		builder.WriteString(r + "\n")
	}
	builder.WriteString("COMMIT\n")

	cmd := exec.Command(common.IptablesRestorePath, "--noflush")
	cmd.Stdin = strings.NewReader(builder.String())

	return cmd.Run()
}
