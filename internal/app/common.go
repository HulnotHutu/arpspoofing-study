package app

import (
	"fmt"
	"net"
	"net/netip"
)

const macAddrLen = 6

type Endpoint struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

func GetInterface(ifname string) (*net.Interface, netip.Addr, error) {
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

func ParseIPv4(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return ip, nil
}

func ParseMAC(s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %s", s)
	}
	return mac, nil
}
