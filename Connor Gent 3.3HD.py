mport time
import logging
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP

closed_ports = 0
open_ports = []
ip = '192.168.1.1'

def is_up(ip):
    icmp = IP(dst=ip) / ICMP()
    resp = sr1(icmp, timeout=10)
    if resp == None:
        return False
    else:
        return True

if __name__ == '__main__':
    conf.verb = 0

    s_time = time.time()

    ports = range(1, 1024)

    if is_up(ip):

        print(" Host " + ip + " is up. Starting scan:")

        for port in ports:
            packet = IP(dst=ip) / TCP(dport=port, flags='S')
            answers, un_answered = sr(packet, timeout=0.2)

            for req, resp in answers:
                if not resp.haslayer(TCP):
                    continue
                tcp_layer = resp.getlayer(TCP)
                if tcp_layer.flags == 0x12:
                    open_ports.append(tcp_layer.sport)
                    sr(IP(dst=ip) / TCP(dport=port, flags='AR'), timeout=1)

        print("OPEN PORTS:")
        for p in open_ports:
            print(p)

        dur = time.time() - s_time
        print("Scan of " + str(ip) + " completed in " + str(dur) + " seconds.")

    else:
        print("Host " + ip + " is down. ")
