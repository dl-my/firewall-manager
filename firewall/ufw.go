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

type UFWManager struct {
	cache *RuleCache[model.Rule]
	sync.RWMutex
}

// UFWAvailable 检查ufw是否可用
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
		cache: NewRuleCache[model.Rule](),
	}
	if err := m.loadRules(); err != nil {
		logs.Error("[ufw] 加载规则失败", zap.Error(err))
		return nil, err
	}
	// 启动时自动恢复 JSON 中的规则
	//if err := m.autoRestoreRules(); err != nil {
	//	logs.Error("[ufw] 启动时规则恢复失败", zap.Error(err))
	//}
	return m, nil
}

func (m *UFWManager) loadRules() error {
	m.cache = NewRuleCache[model.Rule]() // 确保每次重新加载前清空

	out, err := exec.Command("ufw", "status", "numbered").Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")
	rules := utils.UFWParseRules(lines)

	m.Lock()
	defer m.Unlock()
	for _, r := range rules {
		m.cache.Add(r, utils.IndexKey(r))
	}
	logs.Info("[ufw] 规则已加载", zap.Any("rules", rules))
	return nil
}

// autoRestoreRules 启动时自动恢复 JSON 文件中的规则
func (m *UFWManager) autoRestoreRules() error {
	if _, err := os.Stat(common.UFWRulesFile); os.IsNotExist(err) {
		logs.Warn("[ufw] 未找到规则文件, 跳过恢复")
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
		if !m.cache.Exists(utils.IndexKey(r)) {
			// 构造 RuleRequest 并添加
			req := model.RuleRequest(r)
			if err = m.AddRule(context.Background(), req); err != nil {
				logs.Warn("[ufw] 恢复规则失败", zap.Error(err))
			}
		}
	}
	logs.Info("[ufw] 规则已加载", zap.Any("rules", savedRules))
	return nil
}

func (m *UFWManager) AddRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Add)
}

func (m *UFWManager) DeleteRule(ctx context.Context, req model.RuleRequest) error {
	return m.applyRules(ctx, req, common.Delete)
}

func (m *UFWManager) EditRule(ctx context.Context, edit model.EditRuleRequest) error {
	return m.cache.EditRuleGeneric(ctx, edit, m.DeleteRule, m.AddRule, m.Type())
}

func (m *UFWManager) ListRule() []model.Rule {
	rules := m.cache.ToRules()
	return rules
}

func (m *UFWManager) Reload() error {
	zap.L().Debug("[ufw] 开始重载")
	out, err := exec.Command("ufw", "reload").CombinedOutput()
	if err != nil {
		logs.Error("[ufw] 重载失败: ", zap.Error(err), zap.String("output", string(out)))
		return err
	}
	// 重载系统配置及自定义规则
	//err = m.loadRules()
	//if err != nil {
	//	zap.L().Error("[ufw] 重载失败: ", zap.Error(err))
	//	return err
	//}
	//return m.autoRestoreRules()
	if err := m.loadRules(); err != nil {
		logs.Error("[ufw] 规则加载失败", zap.Error(err))
		return err
	}
	return nil
}

func (m *UFWManager) Type() string {
	return "ufw"
}

func (m *UFWManager) SaveRules() error {
	m.RLock()
	defer m.RUnlock()
	if err := m.cache.saveRulesToFileUnlocked(common.UFWRulesFile); err != nil {
		logs.Error("[ufw] 保存规则失败", zap.Error(err))
		return err
	}
	return nil
}

// applyRules 统一的规则增删方法
func (m *UFWManager) applyRules(ctx context.Context, req model.RuleRequest, method string) error {
	rule, err := requestToRule(req)
	if err != nil {
		logs.Error("[ufw] 转换规则失败", zap.Error(err))
		return err
	}

	action := strings.ToLower(rule.Action)
	var processedRules []model.Rule

	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}

		if !utils.IsValidIP(singleRule.SourceIPs[0]) {
			return fmt.Errorf("[ufw] %s规则失败，无效的IP地址: %s", method, ip)
		}

		exists := m.cache.Exists(utils.IndexKey(singleRule))
		if (method == common.Add && exists) || (method == common.Delete && !exists) {
			continue
		}

		args, err := buildUFWCommandArgs(singleRule, action, method)
		if err != nil {
			return fmt.Errorf("[ufw] build ufw args failed: %w", err)
		}

		if out, err := exec.Command("ufw", args...).CombinedOutput(); err != nil {
			logs.ErrorCtx(ctx, fmt.Sprintf("[ufw] %s规则失败", method),
				zap.String("output", string(out)),
				zap.Error(err))
			return err
		}

		processedRules = append(processedRules, singleRule)
	}

	if len(processedRules) == 0 {
		return nil
	}

	// 修改缓存（只在需要时加锁）
	m.Lock()
	defer m.Unlock()
	if method == common.Add {
		for _, r := range processedRules {
			m.cache.Add(r, utils.IndexKey(r))
		}
	} else {
		m.cache.Remove(processedRules)
	}

	logs.InfoCtx(ctx, fmt.Sprintf("[ufw] %s规则成功", method), zap.Any("rules", processedRules))
	return nil
}

func buildUFWCommandArgs(rule model.Rule, action, method string) ([]string, error) {
	ip := rule.SourceIPs[0]
	var args []string
	if method == common.Delete {
		args = append(args, common.Delete)
	}
	args = append(args, action)

	service := strings.ToLower(utils.GetServiceByPort(rule.Port, rule.Protocol))
	switch rule.Chain {
	case "INPUT":
		if service != "" {
			args = append(args, "from", ip, "to", "any", "app", service)
		} else {
			args = append(args, "from", ip, "to", "any", "port",
				fmt.Sprint(rule.Port), "proto", rule.Protocol)
		}
	case "OUTPUT":
		if service != "" {
			args = append(args, "out", "to", ip, "app", service)
		} else {
			args = append(args, "out", "to", ip, "port",
				fmt.Sprint(rule.Port), "proto", rule.Protocol)
		}
	default:
		return nil, fmt.Errorf("[ufw] 不支持的链: %s", rule.Chain)
	}
	return args, nil
}

func requestToRule(req model.RuleRequest) (model.Rule, error) {
	action, ok := common.UFWActionMap[strings.ToUpper(req.Action)]
	if !ok {
		return model.Rule{}, fmt.Errorf("[ufw] 不支持的动作: %s", req.Action)
	}
	chain, ok := common.UFWChainMap[strings.ToUpper(req.Chain)]
	if !ok {
		return model.Rule{}, fmt.Errorf("[ufw] 不支持的链: %s", req.Chain)
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
