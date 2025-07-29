# 防火墙管理系统文档

## 项目简介

本项目是一个用 Go 语言编写的防火墙规则管理服务，目前支持iptables、firewalld、ufw三种防火墙管理。它提供统一的 API 接口，实现防火墙规则的增删改查、批量恢复、规则持久化等功能，适用于云服务器、容器等多种场景。

> 运行前至少需要先安装其中一种。可在config.yaml自行填写管理的防火墙，不填写则自动检测可用的防火墙。

## 项目结构

```
firewall-manager/
├── api/                # HTTP API 路由与处理
├── common/             # 常量、日志、通用工具
│   ├── common/
│   ├── logs/
│   └── utils/
├── config/             # 配置文件与加载
├── firewall/           # 各防火墙管理器及通用逻辑
│   ├── base_rule.go
│   ├── firewalld.go
│   ├── iptables.go
│   ├── manager.go
│   └── ufw.go
├── logs/               # 日志文件
├── middleware/         # 中间件
├── model/              # 规则等数据结构
├── router/             # 路由注册
├── app                 # 项目二进制文件
├── config.yaml         # 配置文件
├── main.go             # 程序入口
└── README.md           # 项目说明       
```

## 核心设计

- 统一接口：所有防火墙管理器实现统一接口 FirewallManager，便于扩展和调用。
- 通用缓存结构：通过泛型 RuleCache 管理规则缓存、索引、并发安全。
- 规则持久化：支持规则的 JSON 持久化（程序退出自动持久化）与自动恢复。
- 日志记录：通过日志类型将日志存放在不同文件中，便于快速排查错误
- API 支持：通过 RESTful API 提供规则管理能力。

## API 调用

- 增加规则：POST  /firewall/add

- 删除规则：POST  /firewall/delete

- 编辑规则：POST  /firewall/edit

- 查询规则：GET    /firewall/list

- 重载规则：POST  /firewall/reload

具体参数见 model/rule.go

## 项目部署

本地部署

```bash
# 克隆项目
git clone https://github.com/dl-my/firewall-manager.git

# 进入项目目录
cd firewall-manager

# 授权可执行权限
chmod +x app

# 直接运行
./app
```

Docker方式

```bash
# 克隆项目
git clone https://github.com/dl-my/firewall-manager.git

# 进入项目目录
cd firewall-manager

# 根据系统修改 Dockerfile 后构建镜像
docker build --network=host -t firewall-manager:latest .

# 启动容器
docker run -d \
  --name firewall-manager \
  --net=host \
  --privileged \
  -v $(pwd)/logs:/root/logs \
  -v $(pwd)/config.yaml:/root/config.yaml \
  -v /var/run/dbus:/var/run/dbus \
  -v /etc/ufw:/etc/ufw \
  -v /lib/ufw:/lib/ufw \
  -v /var/lib/ufw:/var/lib/ufw \
  firewall-centos:latest
```