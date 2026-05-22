# ARP 欺骗教学实验

观察 ARP 报文结构、ARP 缓存更新行为，以及 RFC 826 中 ARP request/reply 字段的含义。

## 文件说明

- `exp.c`：监听指定网卡上的 ARP request，并在匹配目标条件时发送 ARP reply。
- `arp.txt`：RFC 826 文档，用于对照 ARP 字段定义。

## 编译

```bash
go build -o exp-go exp.go
```

## 运行参数

```bash
sudo ./exp-go <interface> <victim_ip> <spoofed_ip>
```

参数含义：

- `<interface>`：监听和发送 ARP 报文的网卡名。
- `<victim_ip>`：只响应来自该 IP 的 ARP request。
- `<spoofed_ip>`：在 ARP reply 中声明为本机 MAC 对应的 IP。

程序需要 root 权限，或具备 `CAP_NET_RAW` 能力。

## 协议字段对应关系

当程序捕获到来自 `victim_ip`、询问 `spoofed_ip` 的 ARP request 时，构造的 ARP reply 字段为：

```text
Ethernet destination = requester MAC
Ethernet source      = local MAC

ar$op  = REPLY
ar$sha = local MAC
ar$spa = spoofed_ip
ar$tha = requester MAC
ar$tpa = requester IP
```

这对应 RFC 826 中的字段：

- `ar$sha`：sender hardware address
- `ar$spa`：sender protocol address
- `ar$tha`：target hardware address
- `ar$tpa`：target protocol address

## 观察

重点观察：

- ARP request 中的 sender/target 字段。
- ARP reply 中 `is-at` 声明的 IP 与 MAC。
- 受害主机 ARP 缓存是否发生变化。

