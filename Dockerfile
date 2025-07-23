# 第一阶段：编译阶段（使用官方 Go 镜像）
FROM golang:1.24-alpine AS builder

# 设置工作目录
WORKDIR /app

ENV GOPROXY=https://goproxy.cn,direct

# 复制 go.mod 和 go.sum 并下载依赖（利用 Docker 缓存）
COPY go.mod go.sum ./
RUN go mod download

# 复制项目所有代码
COPY . .

# 交叉编译为 Linux 可执行文件（确保与目标系统架构一致）
# 设置环境变量：目标 OS 为 Linux，架构为 amd64（根据实际调整）
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# 编译项目，输出可执行文件到 /app/firewall-manager
RUN go build -o firewall-manager ./main.go


# 第二阶段：运行阶段（使用轻量级基础镜像，无需 Go 环境）
FROM alpine:latest

# 设置工作目录
WORKDIR /root/

# 从编译阶段复制可执行文件到当前镜像
COPY --from=builder /app/firewall-manager .

# 复制项目其他必要文件（如配置文件、静态资源等，根据实际需求添加）
COPY config.yaml ./

# 暴露应用端口（根据项目实际端口修改）
EXPOSE 8688

# 启动应用
CMD ["./firewall-manager"]
