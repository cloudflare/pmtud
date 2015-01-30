// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/time.h>

#include "pmtud.h"

const char *optstring_from_long_options(const struct option *opt)
{
	static char optstring[256] = {0};
	char *osp = optstring;

	for (; opt->name != NULL; opt++) {
		if (opt->flag == 0 && opt->val > 0 && opt->val < 256) {
			*osp++ = opt->val;
			switch (opt->has_arg) {
			case optional_argument:
				*osp++ = ':';
				*osp++ = ':';
				break;
			case required_argument:
				*osp++ = ':';
				break;
			}
		}
	}
	*osp++ = '\0';

	if (osp - optstring >= (int)sizeof(optstring)) {
		abort();
	}

	return optstring;
}

int set_core_dump(int enable)
{
	struct rlimit limit;
	limit.rlim_cur = limit.rlim_max = 0;
	if (enable) {
		limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
	}
	return setrlimit(RLIMIT_CORE, &limit);
}

const char *str_quote(const char *s)
{
	static char buf[1024];
	int r = snprintf(buf, sizeof(buf), "\"%.*s\"", (int)sizeof(buf) - 4, s);
	if (r >= (int)sizeof(buf)) {
		buf[sizeof(buf) - 1] = 0;
	}
	return buf;
}

const char *HEX_CHARS = "0123456789abcdef";

const char *to_hex(const uint8_t *s, int len)
{
	static char buf[1024 + 2];
	if (len > 512) {
		len = 512;
	}

	char *p = buf;
	int i;
	for (i = 0; i < len; i++) {
		p[i * 2] = HEX_CHARS[s[i] >> 4];
		p[i * 2 + 1] = HEX_CHARS[s[i] & 0x0f];
	}
	p[len] = 0x00;
	return buf;
}

int signal_desc(int signal)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, signal);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		PFATAL("sigprocmask(SIG_BLOCK, [%i])", signal);
	}

	int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sfd == -1) {
		PFATAL("signalfd()");
	}
	return sfd;
}
