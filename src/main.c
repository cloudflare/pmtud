#include <getopt.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pmtud.h"
#include "uevent.h"

static void usage()
{
	fprintf(stderr,
		"Usage:\n"
		"\n"
		"    pmtud [options] \n"
		"\n"
		"Path MTU daemon is a program that captures and broadcasts "
		"ICMP\n"
		"messages related to MTU detection. It listens on an "
		"interface,\n"
		"waiting for ICMP messages (ip type 3 code 4 or ipv6 type 2 "
		"code 0)\n"
		"and it forwards them verbatim to broadcast ethernet address.\n"
		"\n"
		"Options:\n"
		"\n"
		"  --iface              Network interface to listen on\n"
		"  --src-rate           Pps limit from single source "
		"(default=10 pss)\n"
		"  --iface-rate         Pps limit to send on a single "
		"interface "
		"(default=100 pps)\n"
		"  --help               Print this message\n"
		"\n"
		"Example:\n"
		"\n"
		"    pmtud --iface=eth2 --src-rate=1.0 --iface-rate=10.0\n"
		"\n");
}

#define SNAPLEN 2048
#define BPF_FILTER                                                             \
	"((icmp and icmp[0] == 3 and icmp[1] == 4) or "                        \
	" (icmp6 and ip6[40+0] == 2 and ip6[40+1] == 0)) and"                  \
	"(ether dst not ff:ff:ff:ff:ff:ff)"

static int on_signal(struct uevent *uevent, int sfd, int mask, void *userdata)
{
	int *done = userdata;
	int buf[512];
	/* Drain. Socket should be NONBLOCK */
	int r = read(sfd, buf, sizeof(buf));
	if (r < 0) {
		PFATAL("read()");
	}

	*done = 1;
	return 0;
}
static int handle_pcap(struct uevent *uevent, int sfd, int mask,
		       void *userdata);

struct state
{
	pcap_t *pcap;
	int raw_sd;
};

int main(int argc, char *argv[])
{

	static struct option long_options[] = {
		{"iface", required_argument, 0, 'i'},
		{"src-rate", required_argument, 0, 's'},
		{"iface-rate", no_argument, 0, 'r'},
		{"help", no_argument, 0, 'h'},
		{NULL, 0, 0, 0}};

	const char *optstring = optstring_from_long_options(long_options);
	const char *iface = NULL;

	double src_rate = 10;
	double iface_rate = 100;

	optind = 1;
	while (1) {
		int option_index = 0;

		int arg = getopt_long(argc, argv, optstring, long_options,
				      &option_index);
		if (arg == -1) {
			break;
		}

		switch (arg) {
		case 0:
			FATAL("Unknown option: %s", argv[optind]);
			break;
		case 'h':
			usage();
			break;
		case '?':
			exit(-1);
			break;

		case 'i':
			iface = optarg;
			break;
		case 's':
			src_rate = atof(optarg);
			break;
		case 'r':
			iface_rate = atof(optarg);
			break;

		default:
			FATAL("Unknown option %c: %s", arg,
			      str_quote(argv[optind]));
		}
	}

	if (argv[optind]) {
		FATAL("Not sure what you mean by %s", str_quote(argv[optind]));
	}

	if (iface == NULL) {
		FATAL("Specify interface with --iface option");
	}

	if (set_core_dump(1) < 0) {
		ERRORF("[ ] Failed to enable core dumps");
	}

	struct pcap_stat stats = {0, 0, 0};
	struct state state;
	state.pcap = setup_pcap(iface, BPF_FILTER, SNAPLEN, &stats);
	state.raw_sd = setup_raw(iface);

	int pcap_fd = pcap_get_selectable_fd(state.pcap);
	if (pcap_fd < 0) {
		PFATAL("pcap_get_selectable_fd()");
	}

	int done = 0;
	struct uevent uevent;
	uevent_new(&uevent);
	uevent_yield(&uevent, signal_desc(SIGINT), UEVENT_READ, on_signal,
		     &done);
	uevent_yield(&uevent, signal_desc(SIGTERM), UEVENT_READ, on_signal,
		     &done);
	uevent_yield(&uevent, pcap_fd, UEVENT_READ, handle_pcap, &state);

	fprintf(stderr, "[*] #%i, Started pmtud iface=%s\n", getpid(),
		str_quote(iface));

	while (done == 0) {
		struct timeval timeout =
			NSEC_TIMEVAL(MSEC_NSEC(24 * 60 * 60 * 1000UL));
		int r = uevent_select(&uevent, &timeout);
		if (r != 0) {
			continue;
		}
	}
	fprintf(stderr, "[*] #%i, Quitting\n", getpid());

	unsetup_pcap(state.pcap, iface, &stats);
	fprintf(stderr, "[*] #%i, recv=%i drop=%i ifdrop=%i\n", getpid(),
		stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

	close(state.raw_sd);

	return 0;
}

static int handle_packet(struct state *state, const uint8_t *p, int data_len);

static int handle_pcap(struct uevent *uevent, int sfd, int mask, void *userdata)
{
	struct state *state = userdata;

	while (1) {
		struct timespec ts = (struct timespec){0, 0};

		struct pcap_pkthdr *hdr;
		const uint8_t *data;

		int r = pcap_next_ex(state->pcap, &hdr, &data);

		switch (r) {
		case 1:
			ts = NSEC_TIMESPEC(TIMEVAL_NSEC(&hdr->ts));
			if (hdr->len == hdr->caplen) {
				handle_packet(state, data, hdr->caplen);
			} else {
				/* Partial caputre */
			}
			break;

		case 0:
			/* Timeout */
			return 0;

		case -1:
			FATAL("pcap_next_ex(): %s", pcap_geterr(state->pcap));
			break;

		case -2:
			return 0;
		}
	}
}

static int handle_packet(struct state *state, const uint8_t *p, int data_len)
{
	/* assumming DLT_EN10MB */

	/* 14 ethernet, 20 ipv4, 8 icmp, 8 IPv4 on payload */
	if (data_len < 14 + 20 + 8 + 8) {
		return 0;
	}

	if (p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff &&
	    p[4] == 0xff && p[5] == 0xff) {
		return 0;
	}

	int l3_offset = 14;
	uint16_t eth_type = (((uint16_t)p[12]) << 8) | (uint16_t)p[13];
	if (eth_type == 0x8100) {
		eth_type = (((uint16_t)p[16]) << 8) | (uint16_t)p[17];
		l3_offset = 18;
	}

	int valid = 0;
	if (eth_type == 0x0800 && (p[l3_offset] & 0xF0) == 0x40) {
		uint8_t protocol = p[l3_offset + 9];
		if (protocol == 1 && data_len >= l3_offset + 20 + 8 + 8) {
			valid = 1;
		}
	}

	if (eth_type == 0x86dd && (p[l3_offset] & 0xF0) == 0x60) {
		uint8_t protocol = p[l3_offset + 6];
		if (protocol == 58 && data_len >= l3_offset + 40 + 8 + 32) {
			valid = 1;
		}
	}

	if (valid == 0) {
		return 0;
	}

	uint8_t dst_mac[6];
	memcpy(dst_mac, p, 6);

	/* allright, write there anyway */
	uint8_t *pp = (uint8_t *)p;

	int i;
	for (i = 0; i < 6; i++) {
		pp[i] = 0xff;
	}

	for (i = 0; i < 6; i++) {
		pp[6 + i] = dst_mac[i];
	}

	/* printf("> %s\n", to_hex(pp, data_len)); */

	int r = send(state->raw_sd, pp, data_len, 0);
	if (r < 0) {
		PFATAL("send()");
	}
	return 1;
}
