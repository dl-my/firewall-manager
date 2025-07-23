package logs

import (
	"firewall-manager/config"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"time"
)

var Logger *zap.Logger

func InitLogger(config config.LogConfig) {
	level := getZapLevel(config.Level)

	infoCore := getEncoderCore(fmt.Sprintf("%s/%s-info.log", config.LogDir, today()), config, zapcore.InfoLevel)
	warnCore := getEncoderCore(fmt.Sprintf("%s/%s-warn.log", config.LogDir, today()), config, zapcore.WarnLevel)
	errorCore := getEncoderCore(fmt.Sprintf("%s/%s-error.log", config.LogDir, today()), config, zapcore.ErrorLevel)

	cores := []zapcore.Core{infoCore, warnCore, errorCore}

	//logFile := fmt.Sprintf("%s/%s.log", config.LogDir, today())
	//core := getEncoderCore(logFile, config, zapcore.DebugLevel) // DebugLevel 及以上都记录
	//
	//cores := []zapcore.Core{core}

	if config.LogInConsole {
		consoleCore := zapcore.NewCore(getEncoder(config), zapcore.Lock(os.Stdout), level)
		cores = append(cores, consoleCore)
	}

	Logger = zap.New(zapcore.NewTee(cores...),
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	zap.ReplaceGlobals(Logger)
}

func getEncoderCore(filename string, cfg config.LogConfig, level zapcore.Level) zapcore.Core {
	writer := getLogWriter(filename, cfg)
	encoder := getEncoder(cfg)
	return zapcore.NewCore(encoder, zapcore.AddSync(writer), zap.LevelEnablerFunc(func(l zapcore.Level) bool {
		return l == level
	}))
}

func getEncoder(cfg config.LogConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05")
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.TimeKey = "time"
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "message"

	if cfg.ShowLine {
		encoderConfig.CallerKey = "caller"
	}

	if cfg.Format == "json" {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

func getLogWriter(filename string, cfg config.LogConfig) zapcore.WriteSyncer {
	return zapcore.AddSync(&lumberjack.Logger{
		Filename:   filename,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	})
}

func getZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func today() string {
	return time.Now().Format("2006-01-02")
}
