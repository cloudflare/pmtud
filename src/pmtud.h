// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#define ERRORF(x...) fprintf(stderr, x)

#define FATAL(x...)                                                            \
	do {                                                                   \
		ERRORF("[-] PROGRAM ABORT : " x);                              \
		ERRORF("\n\tLocation : %s(), %s:%u\n\n", __FUNCTION__,         \
		       __FILE__, __LINE__);                                    \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define PFATAL(x...)                                                           \
	do {                                                                   \
		ERRORF("[-] SYSTEM ERROR : " x);                               \
		ERRORF("\n\tLocation : %s(), %s:%u\n", __FUNCTION__, __FILE__, \
		       __LINE__);                                              \
		perror("      OS message ");                                   \
		ERRORF("\n");                                                  \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)
#define TIMEVAL_NSEC(ts)                                                       \
	((ts)->tv_sec * 1000000000ULL + (ts)->tv_usec * 1000ULL)
#define NSEC_TIMESPEC(ns)                                                      \
	(struct timespec) { (ns) / 1000000000ULL, (ns) % 1000000000ULL }
#define NSEC_TIMEVAL(ns)                                                       \
	(struct timeval)                                                       \
	{                                                                      \
		(ns) / 1000000000ULL, ((ns) % 1000000000ULL) / 1000ULL         \
	}
#define MSEC_NSEC(ms) ((ms)*1000000ULL)

/* utils.c */
const char *optstring_from_long_options(const struct option *opt);
int set_core_dump(int enable);
const char *str_quote(const char *s);
const char *to_hex(const uint8_t *s, int len);
int signal_desc(int signal);
const char **parse_argv(const char *str, char delim);

/* pcap.c */
pcap_t *setup_pcap(const char *iface, const char *bpf_filter, int snap_len,
		   struct pcap_stat *stats);
void unsetup_pcap(pcap_t *pcap, const char *iface, struct pcap_stat *stats);
int setup_raw(const char *iface);
const char *ip_to_string(const uint8_t *p, int p_len);

/* sched.c */
int taskset(int taskset_cpu);

/* bitmap.c */
uint64_t *bitmap_alloc(unsigned bits);
void bitmap_free(uint64_t *map);
void bitmap_set(uint64_t *map, unsigned bitno);
int bitmap_get(uint64_t *map, unsigned bitno);

/* nflog.c */
struct nflog *nflog_alloc(uint16_t group_no, unsigned queue_maxlen,
			  int (*user_cb)(const uint8_t *buf, unsigned buf_sz,
					 void *),
			  void *userdata);
void nflog_free(struct nflog *n);
int nflog_get_fd(struct nflog *n);
int nflog_go_handle(struct nflog *n, const uint8_t *buf, unsigned buf_sz);
