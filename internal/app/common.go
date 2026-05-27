package app

import (
	"encoding/binary"
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

// BuildARPFrame 构建完整的 Ethernet + ARP 帧（42 字节），无外部依赖。
func BuildARPFrame(srcMAC net.HardwareAddr, srcIP netip.Addr, dstMAC net.HardwareAddr, dstIP netip.Addr, op uint16) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], dstMAC)               // Ethernet: destination MAC
	copy(frame[6:12], srcMAC)              // Ethernet: source MAC
	binary.BigEndian.PutUint16(frame[12:14], 0x0806) // EtherType ARP
	binary.BigEndian.PutUint16(frame[14:16], 1)      // Hardware: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // Protocol: IPv4
	frame[18] = 6                                     // HW addr length
	frame[19] = 4                                     // Proto addr length
	binary.BigEndian.PutUint16(frame[20:22], op)      // Operation
	copy(frame[22:28], srcMAC)             // Sender HW addr
	srcIPBytes := srcIP.AsSlice()
	copy(frame[28:32], srcIPBytes[:4])     // Sender proto addr
	copy(frame[32:38], dstMAC)             // Target HW addr
	dstIPBytes := dstIP.AsSlice()
	copy(frame[38:42], dstIPBytes[:4])     // Target proto addr
	return frame
}
