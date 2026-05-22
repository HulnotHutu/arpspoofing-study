package main

import (
	"fmt"
	"net"
	"net/netip"

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

type endpoint struct {
	ip  netip.Addr
	mac net.HardwareAddr
}

func writeARPReply(client *arp.Client, src, dst endpoint) error {
	packet, err := arp.NewPacket(arp.OperationReply, src.mac, src.ip, dst.mac, dst.ip)
	if err != nil {
		return err
	}
	return client.WriteTo(packet, dst.mac)
}
