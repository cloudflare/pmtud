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

/* pcap.c */
pcap_t *setup_pcap(const char *iface, const char *bpf_filter, int snap_len,
		   struct pcap_stat *stats);
void unsetup_pcap(pcap_t *pcap, const char *iface, struct pcap_stat *stats);
int setup_raw(const char *iface);
const char *ip_to_string(const uint8_t *p, int p_len);

/* sched.h */
int taskset(int taskset_cpu);
