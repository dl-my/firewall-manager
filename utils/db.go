package utils

import (
	"firewall-manager/config"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%t&loc=%s",
		config.GlobalConfig.DB.Username,
		config.GlobalConfig.DB.Password,
		config.GlobalConfig.DB.Host,
		config.GlobalConfig.DB.Port,
		config.GlobalConfig.DB.Name,
		config.GlobalConfig.DB.Charset,
		config.GlobalConfig.DB.ParseTime,
		config.GlobalConfig.DB.Loc,
	)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		zap.L().Error("数据库连接失败", zap.Error(err))
	}

	// 自动迁移
	err = DB.AutoMigrate(&model.Rule{})
	if err != nil {
		zap.L().Error("自动迁移失败", zap.Error(err))
	}
	fmt.Println("数据库连接成功")
}
