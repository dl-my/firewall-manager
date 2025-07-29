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
	"strings"
	"sync"
)

type IptablesManager struct {
	cache *RuleCache[model.IptablesRule]
	raws  map[string]string // key: IndexKey -> raw rule string
	sync.RWMutex
}

// IPTAvailable 检查iptables是否可用
func IPTAvailable() bool {
	_, err := exec.LookPath(common.IptablesPath)
	return err == nil
}

func NewIptablesManager() (*IptablesManager, error) {
	m := &IptablesManager{
		cache: NewRuleCache[model.IptablesRule](),
		raws:  make(map[string]string),
	}
	// 启动时加载本机现有规则
	if err := m.loadRules(); err != nil {
		logs.Error("[iptables] 加载规则失败", zap.Error(err))
		return nil, err
	}
	return m, nil
}

// LoadRules 拉取系统现有规则到内存
func (m *IptablesManager) loadRules() error {
	m.Lock()
	defer m.Unlock()

	m.cache = NewRuleCache[model.IptablesRule]() // 确保每次重新加载前清空
	m.raws = make(map[string]string)

	lines, err := fetchSystemRules()
	if err != nil {
		return err
	}

	rules := utils.IptablesParseRules(lines)
	for _, r := range rules {
		key := utils.IndexKey(r.Rule)
		m.cache.Add(r, key)
		m.raws[key] = r.Raw
	}

	logs.Info("[iptables] 规则已加载", zap.Any("rules", m.cache.ToRules()))
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
		if !m.cache.Exists(utils.IndexKey(r.Rule)) {
			addedRules = append(addedRules, r)
			rulesBatch = append(rulesBatch, r.Raw)
		}
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
		key := utils.IndexKey(r.Rule)
		m.cache.Add(r, key)
		m.raws[key] = r.Raw
		logs.Info("[iptables] 恢复规则成功", zap.Any("rule", r.Rule))
	}
	logs.Info("[iptables] 规则恢复完成")
	return nil
}

func (m *IptablesManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Add)
}

func (m *IptablesManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Delete)
}

func (m *IptablesManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	return m.cache.EditRuleGeneric(ctx, edit, m.DeleteRule, m.AddRule, m.Type())
}

func (m *IptablesManager) ListRule() []model.Rule {
	allRules := m.cache.ToRules()
	return allRules
}

func (m *IptablesManager) SaveRules() error {
	m.Lock()
	defer m.Unlock()
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		logs.Error("[iptables] 规则保存失败", zap.Error(err))
		return err
	}
	if err := os.WriteFile("./rules.v4", out, 0644); err != nil {
		return err
	}
	if err := m.cache.saveRulesToFileUnlocked(common.IptablesRulesFile); err != nil {
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

// applyRules 统一的规则增删方法
func (m *IptablesManager) applyRules(ctx context.Context, req model.RuleRequest, method string) error {
	rule := model.Rule(req)
	var processedRules []model.IptablesRule
	var processedBatch []string

	// 找到所有需要操作的规则
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		var raw string

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			return fmt.Errorf("[iptables] 删除规则失败，无效的IP地址: %s", ip)
		}
		key := utils.IndexKey(singleRule)
		exists := m.cache.Exists(key)
		if (method == common.Add && exists) || (method == common.Delete && !exists) {
			continue
		}

		if method == common.Add {
			// 检查链是否存在
			if _, err := chainExists(singleRule.Chain); err != nil {
				logs.ErrorCtx(ctx, "[iptables] 添加规则失败", zap.String("链不存在", singleRule.Chain), zap.Error(err))
				return fmt.Errorf("[iptables] %v", err)
			}
			raw = buildIptablesRule(singleRule)
		} else {
			raw = strings.Replace(m.raws[key], "-A", "-D", 1)
		}

		processedBatch = append(processedBatch, raw)
		processedRules = append(processedRules, model.IptablesRule{Rule: singleRule, Raw: raw})
	}

	// 如果没有规则需要操作
	if len(processedBatch) == 0 {
		return nil
	}

	// 使用 iptables-restore 批量操作
	if err := applyRulesWithIptablesRestore(processedBatch); err != nil {
		logs.ErrorCtx(ctx, fmt.Sprintf("[iptables] 批量%s规则失败", method), zap.Error(err))
		return err
	}

	// 从缓存中移除
	m.Lock()
	defer m.Unlock()
	if method == common.Add {
		for _, r := range processedRules {
			key := utils.IndexKey(r.Rule)
			m.cache.Add(r, key)
			m.raws[key] = r.Raw
		}
	} else {
		m.cache.Remove(processedRules)
	}

	logs.InfoCtx(ctx, fmt.Sprintf("[iptables] %s规则成功", method), zap.Any("rules", processedRules))

	return nil
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
		rule.Chain, ipFlag, targetIP, rule.Protocol, rule.Protocol, rule.Port, strings.ToUpper(rule.Action))
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

	cmd := exec.Command(common.IptablesRestorePath, "--noflush", "--verbose")
	cmd.Stdin = strings.NewReader(builder.String())

	// 捕获stderr错误信息
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// 执行命令
	err := cmd.Run()
	if err != nil {
		// 整合所有可能的错误信息
		return fmt.Errorf("iptables-restore 执行失败: %w, 详细错误输出(stderr): %s, 执行的规则内容:%s",
			err, stderr.String(), builder.String())
	}
	return nil
}

func chainExists(chain string) (bool, error) {
	cmd := exec.Command(common.IptablesPath, "-L", chain)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return false, fmt.Errorf("检查链失败: %w, stderr: %s", err, stderr.String())
	}

	return true, nil
}
