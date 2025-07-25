目前支持iptables、firewalld、ufw三种防火墙管理，运行前至少需要先安装其中一种。可在config.yaml自行填写管理的防火墙，不填写则自动检测可用的防火墙。

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

