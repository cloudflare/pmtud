#
# To capture:
#
#     sudo ./pmtud --iface=lo --src-rate=1.0 --iface-rate=10.0 --ports 80 -vvvvv
#

from scapy.all import *
import time
import itertools

ports = [1,2,80,443,444,443|512,8|512]

inet6 = False
inet6_payload = True

if inet6 == False:
    conf.L3socket=L3RawSocket
else:
    conf.L3socket=L3RawSocket6


for i in itertools.count():
    sport=  ports[i % len(ports)]
    if inet6_payload == False:
        payload = (IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=sport,dport=80)/"payload")[IP]
    else:
        payload = (IPv6(src="::1", dst="::1")/TCP(sport=sport,dport=80)/"payload")[IPv6]

    if inet6 == False:
        icmp = IP(dst='127.0.0.1')/ICMP(type=3,code=4,unused=1280)/str(payload)
    else:
        icmp = IPv6(dst='::1')/ICMPv6PacketTooBig(mtu=1280)/str(payload)

    icmp.show()
    send(icmp, iface="lo")
    time.sleep(0.5)
