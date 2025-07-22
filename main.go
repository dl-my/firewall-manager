package main

import (
	"firewall-manager/common/logs"
	"firewall-manager/config"
	"firewall-manager/firewall"
	"firewall-manager/router"
)

func main() {
	config.InitConfig()
	logs.InitLogger(config.GlobalConfig.Log)
	//database.InitDB()
	firewall.InitFirewallManager()

	router.Run(config.GlobalConfig.App.Port)

}
