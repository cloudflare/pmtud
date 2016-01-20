Path MTU daemon
===============

With ECMP enabled the ICMP messages are routed mostly to wrong
server. To fix that let's broadcast the ICMP messages that we think
are worth it to every machine in colo. Some reading:

  * https://tools.ietf.org/html/draft-jaeggli-v6ops-pmtud-ecmp-problem-00


```
$ ./pmtud --help

Usage:

    pmtud [options]

Path MTU Daemon is captures and broadcasts ICMP messages related to
MTU detection. It listens on an interface, waiting for ICMP messages
(IPv4 type 3 code 4 or IPv6 type 2 code 0) and it forwards them
verbatim normally to the broadcast ethernet address. If a list of peers
is given then ICMP messages are forwarded using normal routing to these
peers enabling distribution across different subnets.

Options:

  --iface              Network interface to listen on
  --src-rate           Pps limit from single source (default=1.0 pss)
  --iface-rate         Pps limit to send on a single interface (default=10.0 pps)
  --verbose            Print forwarded packets on screen
  --dry-run            Don't inject packets, just dry run
  --cpu                Pin to particular cpu
  --ports              Forward only ICMP packets with payload
                       containing L4 source port on this list
                       (comma separated)
  --peers              Resend ICMP packets to this peer list
                       (comma separated)
  --help               Print this message

Example:

    pmtud --iface=eth2 --src-rate=1.0 --iface-rate=10.0

```

Once again, it listens waiting for packets matching:

    ((icmp and icmp[0] == 3 and icmp[1] == 4) or
      (icmp6 and ip6[40+0] == 2 and ip6[40+1] == 0)) and
     (ether dst not ff:ff:ff:ff:ff:ff)

And having appropriate length, and forwards them to ethernet broadcast
ff:ff:ff:ff:ff:ff or using normal packet routing if a list of peers
is specified.

To debug use tcpdump:

    sudo tcpdump -s0 -e -ni eth0 '((icmp and icmp[0] == 3 and icmp[1] == 4) or
                                   (icmp6 and ip6[40+0] == 2 and ip6[40+1] == 0))'


To build type:

    git submodule update --init --recursive
    make


To test run it in dry-run and verbose mode:

    sudo ./pmtud --iface=eth0 --dry-run -v -v -v


If you want to use NFLOG interface:

    iptables -I INPUT -i lo -p icmp -m icmp --icmp-type 3/4 --j NFLOG --nflog-group 33
    ip6tables -I INPUT -i lo -p icmpv6 -m icmpv6 --icmpv6-type 2/0 -j NFLOG --nflog-group 33

You can add `-m pkttype ! --pkt-type broadcast` to be even more
specific. Then to use the NFLOG api run:

    sudo ./pmtud --iface=eth0 --dry-run -v -v -v --nflog 33

This will cause `pmtud` to listen to packets from NFLOG and use `eth0`
to brodcast them if neccesary. Debug by listing this /proc file:

    cat /proc/net/netfilter/nfnetlink_log
    33  32781     0 2 65535      0  1

Where columns read:

 * nflog group number of a given queue (16 bits)
 * peer portid: most likely the pid of process
 * number of messages buffered on the kernel side
 * copy mode: 2 for full packet copy
 * copy range: max packet size
 * flush timeout in 1/100th of a second
 * use count

