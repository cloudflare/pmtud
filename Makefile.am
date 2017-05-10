AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = \
	-include src/config.h \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src

EXTRA_DIST = \
	LICENSE-BSD-CloudFlare \
	README.md \
	RELEASE_NOTES \
	tests/replay.py

bin_PROGRAMS = pmtud

pmtud_SOURCES = \
	src/bitmap.c \
	src/csiphash.c \
	src/hashlimit.c \
	src/hashlimit.h \
	src/main.c \
	src/net.c \
	src/nflog.c \
	src/pmtud.h \
	src/sched.c \
	src/uevent.c \
	src/uevent.h \
	src/utils.c

pmtud_CFLAGS = \
	$(PCAP_CFLAGS) \
	$(LIBNETFILTER_LOG_CFLAGS) \
	$(LIBNL_CFLAGS)

pmtud_LDADD = \
	$(PCAP_LIBS) \
	$(LIBNETFILTER_LOG_LIBS) \
	$(LIBNL_LIBS)
