package logs

import (
	"context"
	"firewall-manager/common/utils"
	"go.uber.org/zap"
)

// Info 封装 info 日志
func Info(msg string, fields ...zap.Field) {
	Logger.Info(msg, fields...)
}

func InfoCtx(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("操作ip", utils.GetIP(ctx)))
	Logger.Info(msg, fields...)
}

// Warn 封装 warn 日志
func Warn(msg string, fields ...zap.Field) {
	Logger.Warn(msg, fields...)
}

func WarnCtx(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("操作ip", utils.GetIP(ctx)))
	Logger.Warn(msg, fields...)
}

// Error 封装 error 日志
func Error(msg string, fields ...zap.Field) {
	Logger.Error(msg, fields...)
}

func ErrorCtx(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("操作ip", utils.GetIP(ctx)))
	Logger.Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	Logger.Fatal(msg, fields...)
}
