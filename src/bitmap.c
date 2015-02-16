// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <stdint.h>
#include <stdlib.h>

uint64_t *bitmap_alloc(unsigned bits)
{
	uint64_t *map = calloc(1, (bits + 63) / 64);
	return map;
}

void bitmap_free(uint64_t *map) { free(map); }

void bitmap_set(uint64_t *map, unsigned bitno)
{
	int pos = bitno / 64;
	int bit = bitno % 64;
	map[pos] |= 1ULL << bit;
}

int bitmap_get(uint64_t *map, unsigned bitno)
{
	int pos = bitno / 64;
	int bit = bitno % 64;
	return !!(map[pos] & (1ULL << bit));
}
