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
verbatim to the broadcast ethernet address.

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
  --help               Print this message

Example:

    pmtud --iface=eth2 --src-rate=1.0 --iface-rate=10.0

```

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

