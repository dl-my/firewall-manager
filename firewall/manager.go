package firewall

import (
	"context"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"sync"
)

type FirewallManager interface {
	AddRule(ctx context.Context, rule model.RuleRequest) error
	DeleteRule(ctx context.Context, rule model.RuleRequest) error
	EditRule(ctx context.Context, rule model.EditRuleRequest) error
	ListRule(ctx context.Context) ([]model.Rule, error)
	Reload() error
	Type() string
}

var (
	managerMu sync.RWMutex
	manager   FirewallManager
)

// InitFirewallManager 初始化全局防火墙管理器
func InitFirewallManager() {
	fw, err := detectFirewallManager()
	if err != nil {
		zap.L().Error("初始化防火墙失败", zap.Error(err))
	}
	setManager(fw)
	fmt.Printf("[%s]防火墙初始化成功\n", fw.Type())
}

// detectFirewallManager 自动检测并返回可用的防火墙管理器
func detectFirewallManager() (FirewallManager, error) {
	if UFWAvailable() {
		return NewUFWManager()
	}
	if FWAvailable() {
		return NewFWManager()
	}
	if IPTAvailable() {
		return NewIptablesManager()
	}
	return nil, fmt.Errorf("未检测到可用的防火墙管理器（iptables/ufw）")
}

// setManager 线程安全地设置全局防火墙管理器
func setManager(fw FirewallManager) {
	managerMu.Lock()
	defer managerMu.Unlock()
	manager = fw
}

// GetManager 获取当前全局防火墙管理器（只读）
func GetManager() FirewallManager {
	managerMu.RLock()
	defer managerMu.RUnlock()
	return manager
}
