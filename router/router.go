package router

import (
	"firewall-manager/api"
	"firewall-manager/middleware"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Run(port int) {
	r := gin.Default()

	// 全局使用 IP 中间件
	r.Use(middleware.IPMiddleware(), middleware.Cors())

	// 注册路由
	registerRoutes(r)

	// 启动服务
	if err := r.Run(fmt.Sprintf(":%d", port)); err != nil {
		zap.L().Error("服务启动失败", zap.Error(err))
	}
}

func registerRoutes(r *gin.Engine) {
	firewallApi := r.Group("/firewall")
	{
		firewallApi.POST("/add", api.AddFirewallRule)
		firewallApi.POST("/delete", api.DelFirewallRule)
		firewallApi.POST("/edit", api.EditFirewallRule)
		firewallApi.GET("/list", api.ListFirewallRule)
		firewallApi.POST("/reload", api.ReloadFirewallRule)
	}
}
