package arp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func Request(handle *pcap.Handle, srcip, srcmac, targetip []byte) error {
	if len(srcip) != 4 || len(targetip) != 4 {
		return fmt.Errorf("Ip addresses need to be 4 bytes long")
	}
	if len(srcmac) != 6 {
		return fmt.Errorf("MAC addresses need to be 6 bytes long")
	}
	eth := layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcmac,
		SourceProtAddress: srcip,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetip,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func Reply(handle *pcap.Handle, srcip, srcmac, targetip, targetmac []byte) error {
	if len(srcip) != 4 || len(targetip) != 4 {
		return fmt.Errorf("Ip addresses need to be 4 bytes long")
	}
	if len(srcmac) != 6 || len(targetmac) != 6 {
		return fmt.Errorf("MAC addresses need to be 6 bytes long")
	}

	eth := layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       targetmac,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcmac,
		SourceProtAddress: srcip,
		DstHwAddress:      targetmac,
		DstProtAddress:    targetip,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func Listen(handle *pcap.Handle, iface *net.Interface, out chan *layers.ARP, stop chan struct{}) {
	// Listens for arp packets on iface and will write the arp layer of those packets to the out channel
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case <-stop:
			return
		case packet := <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			out <- arp
		}
	}

}

func FindMAC(ip, srcip net.IP, handle *pcap.Handle, iface *net.Interface) ([]byte, error) {
	stop := make(chan struct{})
	out := make(chan *layers.ARP)
	go Listen(handle, iface, out, stop)
	defer close(stop)
	defer close(out)

	Request(handle, srcip, iface.HardwareAddr, ip)
	for i := 0; i < 10; i++ {
		arp := <-out
		if arp.DstProtAddress.String() == ip.String() {
			return arp.DstHwAddress, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("Could not find %s", ip.String())
}
