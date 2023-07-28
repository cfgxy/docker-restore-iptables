## docker-restore-iptables

```bash
mkdir build
GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -ldflags "-s -w" -o build/docker-restore-iptables-linux-armv7
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o build/docker-restore-iptables-linux-arm64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o build/docker-restore-iptables-linux-amd64
GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -ldflags "-s -w" -o build/docker-restore-iptables-linux-i386
```

iptables-restore 命令执行后会丢失docker服务相关的规则， docker-restore-iptables 用来在不重启docker服务的情况下恢复docker规则

