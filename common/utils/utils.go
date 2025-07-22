package utils

import (
	"context"
	"github.com/gin-gonic/gin"
)

// 为避免 key 冲突，使用私有类型
type contextKey string

const ipKey contextKey = "ip"

// Gin 中间件设置 IP
func SetIPToGinContext(c *gin.Context) {
	c.Set(string(ipKey), c.ClientIP())
}

// 传递到标准 context（service 层使用）
func NewContextWithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey, ip)
}

// 从标准 context 获取 IP
func GetIP(ctx context.Context) string {
	if ip, ok := ctx.Value(ipKey).(string); ok {
		return ip
	}
	return ""
}
