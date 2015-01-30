// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.
//
// Rate limiting algorithm inspired by linux iptables hashlimit module.
// http://lxr.free-electrons.com/source/net/netfilter/xt_hashlimit.c?v=3.17#L383
// http://lxr.free-electrons.com/source/net/sched/sch_tbf.c?v=3.17#L26

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

uint64_t siphash24(const void *src, unsigned long src_sz,
		   const unsigned char key[16]);

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)
#define MSEC_NSEC(ms) ((ms)*1000000ULL)

inline static uint64_t realtime_now()
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return TIMESPEC_NSEC(&now);
}

struct hl_item
{
	uint64_t credit;
	uint64_t prev;
};

struct hashlimit
{
	unsigned size;

	uint64_t credit_max;
	uint64_t touch_cost;
	uint8_t key[16];

	struct hl_item items[0];
};

struct hashlimit *hashlimit_alloc(unsigned size, double rate_pps, double burst)
{
	struct hashlimit *hl = calloc(1, sizeof(struct hashlimit) +
						 size * sizeof(struct hl_item));

	hl->size = size;
	hl->touch_cost = (double)(MSEC_NSEC(1000ULL)) / rate_pps;
	hl->credit_max = burst * hl->touch_cost;

	/* Random numbers for poor */
	uint64_t a = realtime_now() | getpid();
	memcpy(&hl->key[0], &a, 8);
	a = realtime_now() | getppid();
	memcpy(&hl->key[8], &a, 8);

	return hl;
}

void hashlimit_free(struct hashlimit *hl) { free(hl); }

int hashlimit_touch(struct hashlimit *hl, unsigned idx)
{
	struct hl_item *item = &hl->items[idx];

	uint64_t now = realtime_now();
	uint64_t delta = now - item->prev;
	item->credit += delta;
	item->prev = now;

	if (item->credit > hl->credit_max) {
		item->credit = hl->credit_max;
	}

	if (item->credit >= hl->touch_cost) {
		item->credit -= hl->touch_cost;
		return 1;
	}
	return 0;
}

int hashlimit_touch_hash(struct hashlimit *hl, const uint8_t *h, int h_len)
{

	uint64_t hash = siphash24(h, h_len, hl->key);
	return hashlimit_touch(hl, hash % hl->size);
}
