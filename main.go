package main

import (
	"firewall-manager/config"
	"firewall-manager/firewall"
	"firewall-manager/router"
	"firewall-manager/utils"
)

func main() {
	config.InitConfig()
	utils.InitLogger(config.GlobalConfig.Log)
	//utils.InitDB()
	firewall.InitFirewallManager()

	router.Run(config.GlobalConfig.App.Port)

}
