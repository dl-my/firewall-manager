package api

import (
	"firewall-manager/common/common"
	"firewall-manager/common/logs"
	"firewall-manager/common/utils"
	"firewall-manager/firewall"
	"firewall-manager/model"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
)

func AddFirewallRule(c *gin.Context) {
	var rule model.RuleRequest
	// 从 gin 上下文获取
	ip, _ := c.Get(common.IPKey)
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))
	if err := c.ShouldBindJSON(&rule); err != nil {
		logs.ErrorCtx(ctx, "添加规则解析失败", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
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
	// 从 gin 上下文获取
	ip, _ := c.Get(common.IPKey)
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))
	if err := c.ShouldBindJSON(&rule); err != nil {
		logs.ErrorCtx(ctx, "删除规则解析失败", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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
	// 从 gin 上下文获取
	ip, _ := c.Get(common.IPKey)
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))
	if err := c.ShouldBindJSON(&rule); err != nil {
		logs.ErrorCtx(ctx, "编辑规则解析失败", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fw := firewall.GetManager()
	err := fw.EditRule(ctx, rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule edit"})
}

func ListFirewallRule(c *gin.Context) {
	fw := firewall.GetManager()
	// 从 gin 上下文获取
	ip, _ := c.Get(common.IPKey)
	ctx := utils.NewContextWithIP(c.Request.Context(), ip.(string))
	rules := fw.ListRule()
	logs.InfoCtx(ctx, "获取防火墙规则成功", zap.Any("rules", rules))

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
