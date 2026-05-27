//go:build windows

package app

import (
	"bytes"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/gopacket/pcap"
)

// OpenPcap 在 Windows 上通过 Npcap 打开网络接口。
// 先用接口名直连，失败后根据 IP 地址匹配 pcap 设备。
func OpenPcap(ifname string, myIP netip.Addr) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(ifname, 65536, false, -time.Second)
	if err == nil {
		return handle, nil
	}

	devices, listErr := pcap.FindAllDevs()
	if listErr != nil {
		return nil, fmt.Errorf("open %s: %w, list devices: %v", ifname, err, listErr)
	}
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.To4() != nil {
				if bytes.Equal(addr.IP.To4(), myIP.AsSlice()) {
					handle, err = pcap.OpenLive(dev.Name, 65536, false, -time.Second)
					if err == nil {
						return handle, nil
					}
					return nil, fmt.Errorf("open pcap %s: %w", dev.Name, err)
				}
			}
		}
	}
	return nil, fmt.Errorf("no pcap device found for IP %s", myIP)
}
