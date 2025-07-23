package config

import (
	"github.com/spf13/viper"
	"log"
)

type LogConfig struct {
	Level        string `mapstructure:"level" json:"level" yaml:"level"`
	Format       string `mapstructure:"format" json:"format" yaml:"format"`
	LogDir       string `mapstructure:"log_dir" json:"log_dir" yaml:"log_dir"`
	ShowLine     bool   `mapstructure:"show_line" json:"show_line" yaml:"show_line"`
	LogInConsole bool   `mapstructure:"log_in_console" json:"log_in_console" yaml:"log_in_console"`
	MaxSize      int    `mapstructure:"max_size" json:"max_size" yaml:"max_size"`
	MaxBackups   int    `mapstructure:"max_backups" json:"max_backups" yaml:"max_backups"`
	MaxAge       int    `mapstructure:"max_age" json:"max_age" yaml:"max_age"`
	Compress     bool   `mapstructure:"compress" json:"compress" yaml:"compress"`
}

type Database struct {
	Driver    string `mapstructure:"driver" json:"driver" yaml:"driver"`
	Host      string `mapstructure:"host" json:"host" yaml:"host"`
	Port      int    `mapstructure:"port" json:"port" yaml:"port"`
	Username  string `mapstructure:"username" json:"username" yaml:"username"`
	Password  string `mapstructure:"password" json:"password" yaml:"password"`
	Name      string `mapstructure:"name" json:"name" yaml:"name"`
	Charset   string `mapstructure:"charset" json:"charset" yaml:"charset"`
	Loc       string `mapstructure:"loc" json:"loc" yaml:"loc"`
	ParseTime bool   `mapstructure:"parse_time" json:"parse_time" yaml:"parse_time"`
}

type AppConfig struct {
	App struct {
		Port int `mapstructure:"port"`
	}

	DB Database `mapstructure:"database"`

	Log LogConfig `mapstructure:"log"`

	FirewallType string `mapstructure:"firewall_type"`
}

var GlobalConfig AppConfig

func InitConfig() {
	viper.SetConfigFile("config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	if err := viper.Unmarshal(&GlobalConfig); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}

	log.Println("配置加载成功")
}
