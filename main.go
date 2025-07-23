package main

import (
	"firewall-manager/common/logs"
	"firewall-manager/config"
	"firewall-manager/firewall"
	"firewall-manager/router"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config.InitConfig()
	logs.InitLogger(config.GlobalConfig.Log)
	//database.InitDB()
	firewall.InitFirewallManager(config.GlobalConfig.FirewallType)

	setupGracefulShutdown(firewall.GetManager())

	router.Run(config.GlobalConfig.App.Port)

}

// 监听信号并优雅关闭
func setupGracefulShutdown(fw firewall.Manager) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logs.Info("捕获退出信号，正在保存规则", zap.String("type", fw.Type()))
		if err := fw.SaveRules(); err != nil {
			logs.Error("保存规则失败", zap.String("type", fw.Type()), zap.Error(err))
		} else {
			logs.Info("规则保存成功", zap.String("type", fw.Type()))
		}
		time.Sleep(500 * time.Millisecond) // 确保日志输出完毕
		os.Exit(0)
	}()
}
