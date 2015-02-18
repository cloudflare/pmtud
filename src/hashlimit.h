// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

struct hashlimit *hashlimit_alloc(unsigned size, double rate_pps, double burst);
void hashlimit_free(struct hashlimit *hl);

int hashlimit_check(struct hashlimit *hl, unsigned idx);
int hashlimit_check_hash(struct hashlimit *hl, const uint8_t *h, int h_len);

int hashlimit_subtract(struct hashlimit *hl, unsigned idx);
int hashlimit_subtract_hash(struct hashlimit *hl, const uint8_t *h, int h_len);
