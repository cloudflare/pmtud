#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <getopt.h>
#include <pcap.h>
#include "pmtud.h"

#define MAX_BIND_RETRIES 4096

struct nflog
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	int (*user_cb)(const uint8_t *buf, unsigned buf_sz, void *);
	void *userdata;
};

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
	      struct nflog_data *nfa, void *data)
{
	struct nflog *n = data;

	/* We're copying the data over again. This is inefficient but
	 * we compromise to make the interfaces simpler. */
	uint8_t buf[2048];

	const char *l2data = nflog_get_msg_packet_hwhdr(nfa);
	int l2data_len = nflog_get_msg_packet_hwhdrlen(nfa);
	if (l2data_len < 0) {
		return 0;
	}

	if (l2data_len > (int)sizeof(buf)) {
		l2data_len = sizeof(buf);
	}
	memcpy(buf, l2data, l2data_len);

	char *payload;
	int payload_len = nflog_get_payload(nfa, &payload);
	if (payload_len < 0) {
		return 0;
	}

	if (payload_len > (int)sizeof(buf) - l2data_len) {
		payload_len = sizeof(buf) - l2data_len;
	}
	memcpy(&buf[l2data_len], payload, payload_len);

	n->user_cb(buf, payload_len + l2data_len, n->userdata);

	return 0;
}

struct nflog *nflog_alloc(uint16_t group_no, unsigned queue_maxlen,
			  int (*user_cb)(const uint8_t *buf, unsigned buf_sz,
					 void *),
			  void *userdata)
{
	struct nflog *n = calloc(1, sizeof(struct nflog));

	n->user_cb = user_cb;
	n->userdata = userdata;
	n->h = nflog_open();

	int r;
	r = nflog_unbind_pf(n->h, AF_INET);
	if (r < 0) {
		if (errno == EPERM) {
			PFATAL("Can't open netlink descriptor. Are you root?");
		}
		PFATAL("nflog_unbind_pf(AF_INET)");
	}
	r = nflog_unbind_pf(n->h, AF_INET6);
	if (r < 0) {
		PFATAL("nflog_unbind_pf(AF_INET6)");
	}

	r = nflog_bind_pf(n->h, AF_INET);
	if (r < 0) {
		PFATAL("nflog_bind_pf(AF_INET)");
	}
	r = nflog_bind_pf(n->h, AF_INET6);
	if (r < 0) {
		PFATAL("nflog_bind_pf(AF_INET6)");
	}

	/* Binding can fail if the queue is very busy. Let's try
	 * binding a few times before giving up. */
	int retries = MAX_BIND_RETRIES;
	errno = 0;

try_bind_again:
	n->qh = nflog_bind_group(n->h, group_no);
	if (n->qh == NULL) {
		if (errno == EPERM) {
			PFATAL("Can't bind to nflog group %i. Somebody else "
			       "might be using that NFLOG group. Check "
			       "/proc/net/netfilter/nfnetlink_log.",
			       group_no);
		}
		if (errno == 0) {
			// bind_group failed due to too much traffic
			retries -= 1;
			if (retries > 0)
				goto try_bind_again;
		}
		PFATAL("nflog_bind_group %i", errno);
	}

	if (nflog_set_mode(n->qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		PFATAL("nflog_set_mode");
	}

	if (nflog_set_nlbufsiz(n->qh, queue_maxlen * 1500) < 0) {
		PFATAL("nflog_set_mode");
	}

	/* Disable netlink timeout, to reduce latency. The units of
	 * value are 1/100th of second. */
	if (nflog_set_timeout(n->qh, 0) < 0) {
		PFATAL("nflog_set_timeout");
	}

	int fd = nflog_fd(n->h);

	int opt = 1;
	r = setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
	if (r == -1) {
		PFATAL("setsockopt(NETLINK_NO_ENOBUFS)");
	}

	nflog_callback_register(n->qh, &cb, n);
	return n;
}

void nflog_free(struct nflog *n)
{
	nflog_unbind_group(n->qh);
	n->qh = NULL;
	nflog_close(n->h);
	n->h = NULL;
	free(n);
}

int nflog_get_fd(struct nflog *n)
{
	int fd = nflog_fd(n->h);
	if (fd < 0) {
		PFATAL("nflog_fd");
	}

	int r = fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	if (r != 0) {
		PFATAL("fcntl(O_NONBLOCK)");
	}
	return fd;
}

int nflog_go_handle(struct nflog *n, const uint8_t *buf, unsigned buf_sz)
{
	return nflog_handle_packet(n->h, (char *)buf, (int)buf_sz);
}
