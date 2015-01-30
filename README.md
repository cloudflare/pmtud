Path MTU daemon
===============

With ECMP enabled the ICMP messages are routed mostly to wrong
server. To fix that let's broadcast the ICMP messages that we think
are worth it to every machine in colo. Some reading:

  * https://tools.ietf.org/html/draft-jaeggli-v6ops-pmtud-ecmp-problem-00


Path MTU daemon is a program that captures and broadcasts ICMP
messages related to MTU detection. It listens on an interface
waiting for ICMP messages (ip type 3 code 4 or ipv6 type 2 code 0)
and it forwards them verbatim to broadcast ethernet address.

Once again, it listens waiting for packets matching:

    ((icmp and icmp[0] == 3 and icmp[1] == 4) or
      (icmp6 and ip6[40+0] == 2 and ip6[40+1] == 0)) and
     (ether dst not ff:ff:ff:ff:ff:ff)

And having appropriate length, and forwards them to ethernet broadcast
ff:ff:ff:ff:ff:ff.

To debug use tcpdump:

    sudo tcpdump -s0 -e -ni eth0 '((icmp and icmp[0] == 3 and icmp[1] == 4) or
                                   (icmp6 and ip6[40+0] == 2 and ip6[40+1] == 0))'


To build type:

    git submodule update --init --recursive
    make


To test run it in dry-run and verbose mode:

    sudo ./pmtud --iface=eth0 --dry-run -v -v -v

