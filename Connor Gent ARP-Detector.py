from scapy.all import *

print("Created by Connor Gent!")
arp_ = {}


def main():
    packets = rdpcap("capture.pcap")
    print('~~~~~~~~~System - under ARP poisoning attack!!!~~~~~~~~~~\n')
    for pkt in packets:
        if 'ARP' in pkt and pkt.op == 2:
            arp_poision(pkt)
    print('~~~~~~~~~~ARP poisioning detection has finished~~~~~~~\n')


def arp_poision(pkt):
    if pkt.psrc in arp_ and pkt.hwsrc != arp_[pkt.psrc]:
        store_packet(pkt)
    elif pkt.psrc not in arp_.keys():
        for ip in arp_.keys():
            if arp_[ip] == pkt.hwsrc:
                store_packet(pkt)
    arp_[pkt.psrc] = pkt.hwsrc


def store_packet(pkt):
    ip_mac = {'SOURCE': {'MAC': pkt.hwsrc, 'ip_address': pkt.psrc},
              'TARGET': {'MAC': pkt.hwdst, 'ip_address': pkt.pdst},
              }
    print(ip_mac)


if __name__ == "__main__":
    main()
