# ARP 欺骗教学实验

观察 ARP 报文结构、ARP 缓存更新行为，以及 RFC 826 中 ARP request/reply 字段的含义。

## 文件说明

- `cmd/exp-active`：主动向指定目标发送伪造 ARP reply。
- `cmd/exp-passive`：监听指定网卡上的 ARP request，并在匹配目标条件时发送 ARP reply。
- `internal/arpapp`：Go 版本共用的网卡和 IPv4 解析逻辑。
- `legacy/exp.c`：C 语言版本的被动 ARP reply 实验程序。
- `docs/arp.txt`：RFC 826 文档，用于对照 ARP 字段定义。
- `docs/rfc5227.txt`：IPv4 Address Conflict Detection 相关 RFC 文档。

## 编译

```bash
go build -o exp-active ./cmd/exp-active
go build -o exp-passive ./cmd/exp-passive
```

## 运行参数

主动版本会周期性向目标发送伪造 ARP reply：

```bash
sudo ./exp-active -i <interface> -t <target_ip> -s <spoofed_ip>
```

被动版本只在捕获到目标 ARP request 时才回复：

```bash
sudo ./exp-passive -i <interface> -s <spoofed_ip>
```

参数含义：

- `-i`：监听和发送 ARP 报文的网卡名。
- `-t`：主动版本的目标主机 IPv4 地址。
- `-s`：在 ARP reply 中被声明为本机 MAC 对应的 IPv4 地址，常见实验场景是网关 IP。

程序需要 root 权限，或具备 `CAP_NET_RAW` 能力。主动版本停止实验时使用 `Ctrl+C`。

## ARP 欺骗原理

RFC 826 中 ARP 的目标是把协议地址转换为硬件地址。在以太网 IPv4 场景中，就是把 IPv4 地址解析为 48 bit MAC 地址。主机发送数据前，如果不知道下一跳 IP 对应的 MAC，就广播 ARP request；拥有该 IP 的主机返回 ARP reply，声明“这个 IP 对应这个 MAC”。

ARP 报文中最关键的是 sender 字段：

- `ar$sha`：sender hardware address，发送方硬件地址，也就是 MAC。
- `ar$spa`：sender protocol address，发送方协议地址，也就是 IPv4 地址。
- `ar$tha`：target hardware address，目标硬件地址。
- `ar$tpa`：target protocol address，目标协议地址。
- `ar$op`：操作类型，`REQUEST` 表示请求，`REPLY` 表示响应。

RFC 826 的接收流程说明了 ARP 欺骗能够成立的关键原因：接收方在处理 ARP 报文时，会把 `<protocol type, sender protocol address, sender hardware address>` 合并进自己的地址转换表；并且这个合并动作发生在检查 opcode 之前。如果表中已经存在同一个协议地址对应的条目，新收到的 sender hardware address 会覆盖旧值。

因此，ARP 欺骗并不依赖复杂漏洞，而是利用 ARP 协议本身的信任模型：局域网主机通常相信收到的 ARP 声明。攻击者只要向目标发送伪造的 ARP reply，例如声明：

```text
网关 IP is-at 攻击者 MAC
```

目标主机就可能把“网关 IP -> 攻击者 MAC”写入 ARP 缓存。之后目标发往网关的以太网帧会先发到攻击者 MAC。若同时欺骗网关，让网关认为“目标 IP -> 攻击者 MAC”，并开启转发，就形成中间人链路；如果不转发，则可能造成目标通信中断。

本实验程序采用单向、明确目标的方式：主动版本周期性向 `target_ip` 发送 ARP reply，在其中把 `spoofed_ip` 的 MAC 声明为本机 MAC；被动版本在收到针对 `spoofed_ip` 的 ARP request 时返回 ARP reply。

## 协议字段对应关系

程序主动向 `target_ip` 发送伪造 ARP reply 时，报文字段为：

```text
Ethernet destination = target MAC
Ethernet source      = local MAC

ar$op  = REPLY
ar$sha = local MAC
ar$spa = spoofed_ip
ar$tha = target MAC
ar$tpa = target_ip
```

含义是向目标声明：`spoofed_ip` 对应 `local MAC`。这对应 RFC 826 中的字段：

- `ar$sha`：sender hardware address
- `ar$spa`：sender protocol address
- `ar$tha`：target hardware address
- `ar$tpa`：target protocol address

## 观察

重点观察：

- ARP request 中的 sender/target 字段。
- ARP reply 中 `is-at` 声明的 IP 与 MAC。
- 受害主机 ARP 缓存是否发生变化。

