// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

struct hashlimit *hashlimit_alloc(unsigned size, double rate_pps, double burst);
int hashlimit_touch(struct hashlimit *hl, unsigned idx);
int hashlimit_touch_hash(struct hashlimit *hl, const uint8_t *h, int h_len);
void hashlimit_free(struct hashlimit *hl);
