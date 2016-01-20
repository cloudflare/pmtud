// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <errno.h>
#include <getopt.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <sys/ioctl.h>

#include "pmtud.h"

#define MAX_PEERS 32

struct peer
{
        union {
                struct sockaddr_in sin;
                struct sockaddr_in6 sin6;
        } sa;
        socklen_t salen;
};

pcap_t *setup_pcap(const char *iface, const char *bpf_filter, int snap_len,
		   struct pcap_stat *stats)
{

	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *pcap = pcap_create(iface, errbuf);
	if (pcap == NULL) {
		FATAL("pcap_create(%s): %s", str_quote(iface), errbuf);
	}

	int r;

	r = pcap_set_tstamp_type(pcap, PCAP_TSTAMP_ADAPTER_UNSYNCED);
	if (r != 0) {
		pcap_set_tstamp_type(pcap, PCAP_TSTAMP_ADAPTER);
	}

	r = pcap_set_promisc(pcap, 0);
	if (r != 0) {
		FATAL("pcap_set_promisc: %s", pcap_geterr(pcap));
	}

	r = pcap_set_snaplen(pcap, snap_len);
	if (r != 0) {
		FATAL("pcap_set_snaplen: %s", pcap_geterr(pcap));
	}

	r = pcap_set_timeout(pcap, 100 /* ms */);
	if (r != 0) {
		FATAL("pcap_set_timeout: %s", pcap_geterr(pcap));
	}

	r = pcap_activate(pcap);
	if (r != 0) {
		FATAL("pcap_activate(%s): %s", str_quote(iface),
		      pcap_geterr(pcap));
	}

	r = pcap_setdirection(pcap, PCAP_D_IN);
	if (r != 0) {
		FATAL("pcap_setdirection: %s %d", pcap_geterr(pcap), r);
	}

	r = pcap_setnonblock(pcap, 1, errbuf);
	if (r != 0) {
		FATAL("pcap_setnonblock(%s, 1): %s", str_quote(iface), errbuf);
	}

	r = pcap_getnonblock(pcap, errbuf);
	if (r != 1) {
		FATAL("pcap_getnonoblock(): can't set nonblocking!");
	}

	struct bpf_program bpf;

	r = pcap_compile(pcap, &bpf, bpf_filter, 1, PCAP_NETMASK_UNKNOWN);
	if (r != 0) {
		FATAL("pcap_compile(%s): %s", str_quote(bpf_filter),
		      pcap_geterr(pcap));
	}

	r = pcap_setfilter(pcap, &bpf);
	if (r != 0) {
		FATAL("pcap_setfilter(%s): %s", str_quote(bpf_filter),
		      pcap_geterr(pcap));
	}

	pcap_freecode(&bpf);

	r = pcap_datalink(pcap);
	if (r != DLT_EN10MB) {
		FATAL("Only Ethernet devices supported %s is %s",
		      str_quote(iface), pcap_datalink_val_to_name(r));
	}

	r = pcap_stats(pcap, stats);
	if (r != 0) {
		FATAL("pcap_stats(%s): %s", str_quote(iface),
		      pcap_geterr(pcap));
	}

	return pcap;
}

void unsetup_pcap(pcap_t *pcap, const char *iface, struct pcap_stat *stats)
{
	struct pcap_stat stats2 = {0, 0, 0};
	int r = pcap_stats(pcap, &stats2);
	if (r != 0) {
		FATAL("pcap_stats(%s): %s", str_quote(iface),
		      pcap_geterr(pcap));
	}

	stats->ps_recv = stats2.ps_recv - stats->ps_recv;
	stats->ps_drop = stats2.ps_drop - stats->ps_drop;
	stats->ps_ifdrop = stats2.ps_ifdrop - stats->ps_ifdrop;

	pcap_close(pcap);
}

int setup_raw(const char *iface)
{
	int r;
	int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		PFATAL("socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");
	}

	struct ifreq s_ifr;
	memset(&s_ifr, 0, sizeof(s_ifr));
	strncpy(s_ifr.ifr_name, iface, sizeof(s_ifr.ifr_name));
	r = ioctl(s, SIOCGIFINDEX, &s_ifr);
	if (r != 0) {
		PFATAL("ioctl(SIOCGIFINDEX, %s)", str_quote(iface));
	}

	struct sockaddr_ll my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sll_family = AF_PACKET;
	my_addr.sll_protocol = htons(ETH_P_ALL);
	my_addr.sll_ifindex = s_ifr.ifr_ifindex;
	r = bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if (r != 0) {
		PFATAL("bind(%s, AF_PACKET)", str_quote(iface));
	}

	int tmp = 1024 * 1024;
	r = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(tmp));
	if (r != 0) {
		PFATAL("setsockopt(SO_SNDBUF)");
	}

	/* r = fcntl(s, F_SETFL, */
	/* 	  O_NONBLOCK | fcntl(s, F_GETFL, 0)); */
	/* if (r != 0) { */
	/* 	PFATAL("fcntl(O_NONBLOCK)"); */
	/* } */
	return s;
}

const char *ip_to_string(const uint8_t *p, int p_len)
{
	static char dst[INET6_ADDRSTRLEN + 1];
	const char *r = NULL;

	if (p_len == 4) {
		struct in_addr addr;
		memcpy(&addr, p, 4);
		r = inet_ntop(AF_INET, &addr, dst, INET6_ADDRSTRLEN);
	}
	if (p_len == 16) {
		struct in6_addr addr;
		memcpy(&addr, p, 16);
		r = inet_ntop(AF_INET6, &addr, dst, INET6_ADDRSTRLEN);
	}

	if (r == NULL) {
		dst[0] = '?';
		dst[1] = 0x00;
	}
	return dst;
}

void setup_rawipsocket(int *raw4, int *raw6)
{

	*raw4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (*raw4 < 0) {
		PFATAL("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
	}
	*raw6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (*raw6 < 0) {
		PFATAL("socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");
	}
}

struct peer *make_peerlist(const char **addresses)
{
	struct addrinfo hints;
	struct addrinfo *result;
	struct peer *peer_list;
	int r;
	int i;

	peer_list = calloc(MAX_PEERS, sizeof(struct peer));
	if (peer_list == NULL) {
		PFATAL("malloc(peer_list)");
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST;
	for (i = 0; addresses[0] != NULL; addresses++, i++) {
		if (i >= MAX_PEERS) {
			FATAL("Maximum number of peers exceeded %d",
			      MAX_PEERS);
		}
		r = getaddrinfo(addresses[0], NULL, &hints, &result);
		if (r != 0) {
			FATAL("Malformed peer address %s", addresses[0]);
		}
		if (result->ai_addrlen > sizeof(peer_list[i].sa)) {
			FATAL("Internal error in address structures");
		}
		memcpy(&peer_list[i].sa, result->ai_addr, result->ai_addrlen);
		peer_list[i].salen = result->ai_addrlen;
		freeaddrinfo(result);
	}
	return peer_list;
}

void free_peerlist(struct peer *peer_list)
{
	free(peer_list);
}

int check_peerlist(struct peer *peer_list, const uint8_t *p, int p_len)
{
	struct peer *peer;

	for (peer = peer_list; peer < peer_list + MAX_PEERS && peer->salen != 0;
	     peer++) {
		if (p_len == 4 && peer->sa.sin.sin_family == AF_INET) {
			if (memcmp(&peer->sa.sin.sin_addr, p, p_len) == 0) {
				return 0;
			}
		} else if (p_len == 16 && peer->sa.sin6.sin6_family == AF_INET6) {
			if (memcmp(&peer->sa.sin6.sin6_addr, p, p_len) == 0) {
				return 0;
			}
		}
	}
	return -1;
}

void sendto_peerlist(struct peer *peer_list, int raw4, int raw6, int addr_len,
    const uint8_t *icmppkt, unsigned icmppkt_len, int orig_ttl)
{
	struct peer *peer;
	int family;
	int r;
	int ttl;

	if (addr_len == 4) {
		family = AF_INET;
	} else if (addr_len == 16) {
		family = AF_INET6;
	} else {
		FATAL("addr_len is neither 4 nor 16");
	}

	ttl = orig_ttl - 1;
	if (ttl == 0)
		return;
	setsockopt(raw4, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	setsockopt(raw6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl,
		   sizeof(ttl));
	for (peer = peer_list; peer < peer_list + MAX_PEERS && peer->salen != 0;
	     peer++) {
		if (peer->sa.sin.sin_family != family) {
			continue;
		}
		r = sendto((family == AF_INET ? raw4 : raw6),
			   icmppkt, icmppkt_len, 0, (struct sockaddr *)&peer->sa,
			   peer->salen);
		/* ENOBUFS happens during IRQ storms okay to ignore */
		if (r < 0 && errno != ENOBUFS) {
			PFATAL("sendto()");
		}
	}
}
