package firewall

import (
	"context"
	"firewall-manager/common/logs"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"sync"
)

type Manager interface {
	AddRule(ctx context.Context, rule model.RuleRequest) error
	DeleteRule(ctx context.Context, rule model.RuleRequest) error
	EditRule(ctx context.Context, rule model.EditRuleRequest) error
	ListRule() ([]model.Rule, error)
	SaveRules() error
	Reload() error
	Type() string
}

var (
	managerMu sync.RWMutex
	manager   Manager
)

// InitFirewallManager 初始化全局防火墙管理器
func InitFirewallManager(firewallType string) {
	fw, err := detectFirewallManager(firewallType)
	if err != nil {
		logs.Error("初始化防火墙失败", zap.Error(err))
		panic(fmt.Sprintf("初始化防火墙失败: %v\n", err))
		//logs.Fatal("初始化防火墙失败", zap.Error(err))
	}
	setManager(fw)
	fmt.Printf("[%s]防火墙初始化成功\n", fw.Type())
}

// detectFirewallManager 自动检测并返回可用的防火墙管理器
func detectFirewallManager(firewallType string) (Manager, error) {
	// 定义可用的防火墙类型及其检测函数
	firewalls := map[string]struct {
		check func() bool
		init  func() (Manager, error)
	}{
		"ufw": {
			check: UFWAvailable,
			init:  func() (Manager, error) { return NewUFWManager() },
		},
		"firewalld": {
			check: FWAvailable,
			init:  func() (Manager, error) { return NewFWManager() },
		},
		"iptables": {
			check: IPTAvailable,
			init:  func() (Manager, error) { return NewIptablesManager() },
		},
	}

	// 如果用户指定了 firewallType，优先使用
	if fw, ok := firewalls[firewallType]; ok {
		if fw.check() {
			return fw.init()
		}
		return nil, fmt.Errorf("%s 不可用", firewallType)
	}

	// 否则自动检测
	for name, fw := range firewalls {
		if fw.check() {
			zap.L().Warn("未指定防火墙类型，已自动选择", zap.String("type", name))
			return fw.init()
		}
	}

	return nil, fmt.Errorf("未检测到可用的防火墙管理器（ufw/firewalld/iptables）")
}

// setManager 线程安全地设置全局防火墙管理器
func setManager(fw Manager) {
	managerMu.Lock()
	defer managerMu.Unlock()
	manager = fw
}

// GetManager 获取当前全局防火墙管理器（只读）
func GetManager() Manager {
	managerMu.RLock()
	defer managerMu.RUnlock()
	return manager
}
