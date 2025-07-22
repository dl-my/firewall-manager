package middleware

import (
	"firewall-manager/common/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func IPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		utils.SetIPToGinContext(c)
		c.Next()
	}
}

func LogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		zap.L().Info("Request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("ip", c.ClientIP()),
		)
		c.Next()
	}
}
