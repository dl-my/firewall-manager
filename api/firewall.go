package api

import (
	"firewall-manager/common/utils"
	"firewall-manager/firewall"
	"firewall-manager/model"
	"github.com/gin-gonic/gin"
	"net/http"
)

func AddFirewallRule(c *gin.Context) {
	var rule model.RuleRequest
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 从 gin 上下文获取
	ip, _ := c.Get("ip")
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))

	fw := firewall.GetManager()
	err := fw.AddRule(ctx, rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule added"})
}

func DelFirewallRule(c *gin.Context) {
	var rule model.RuleRequest
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 从 gin 上下文获取
	ip, _ := c.Get("ip")
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))

	fw := firewall.GetManager()
	err := fw.DeleteRule(ctx, rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule del"})
}

func EditFirewallRule(c *gin.Context) {
	var rule model.EditRuleRequest
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 从 gin 上下文获取
	ip, _ := c.Get("ip")
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))

	fw := firewall.GetManager()
	err := fw.EditRule(ctx, rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule edit"})
}

func ListFirewallRule(c *gin.Context) {
	// 从 gin 上下文获取
	//ip, _ := c.Get("ip")
	//ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))

	fw := firewall.GetManager()
	rules, err := fw.ListRule()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}
func ReloadFirewallRule(c *gin.Context) {
	fw := firewall.GetManager()
	err := fw.Reload()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"rules": "Rule reload"})
}
