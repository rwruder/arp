I made this package as a simple extension of github.com/google/gopacket

Functions are:

Request(handle *pcap.Handle, srcip, srcmac, targetip []byte) error
    - Sends out a arp Request packet for the target IP address
    - *pcap.Handle from github.com/google/gopacket/pcap
    - srcip IP address of the computer sending the packet
    - srcmac MAC address of the computer sending the packet
    - targetip IP address being queried by the arp request

Reply(handle *pcap.Handle, srcip, srcmac, targetip, targetmac []byte) error
    - Sends out a arp Reply packet to the target IP address claiming srcip and srcmac
    - *pcap.Handle from github.com/google/gopacket/pcap
    - srcip IP address of the computer sending the packet
    - srcmac MAC address of the computer sending the packet
    - targetip IP address being sent the reply
    - targetmac MAC address of the computer being sent the reply

Listen(handle *pcap.Handle, iface *net.Interface, out chan *layers.ARP)
    - Function loops indefinitely and writes arp data to out channel
    - *pcap.Handle from github.com/google/gopacket/pcap
    