#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pmtud],
	[v0.6],
	[help@cloudflare.com], [],
	[https://github.com/cloudflare/pmtud])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([
	1.10
	dist-xz
	foreign
	no-dist-gzip
	subdir-objects
	tar-pax
])

# --enable-silent-rules
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

# Checks for programs.
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99

# libtool
LT_INIT

# Checks for libraries.
m4_ifndef([PKG_PROG_PKG_CONFIG],
  [m4_fatal([Could not locate the pkg-config autoconf
    macros. These are usually located in /usr/share/aclocal/pkg.m4.
    If your macros are in a different location, try setting the
    environment variable AL_OPTS="-I/other/macro/dir" before running
    ./autogen.sh or autoreconf again.])])
PKG_PROG_PKG_CONFIG

AC_ARG_WITH([pcap-config],
	AC_HELP_STRING([--with-pcap-config=FILE], [Use given pcap-config]),
	[pcapcfg="$withval"],
	[AC_PATH_PROG([pcapcfg], [pcap-config])])
AS_IF([test x$pcapcfg = "x"], [AC_MSG_ERROR([cannot find pcap-config])])

PCAP_LIBS=`$pcapcfg --libs`
PCAP_CFLAGS=`$pcapcfg --cflags`
AC_ARG_VAR([PCAP_LIBS], [PCAP library files])
AC_ARG_VAR([PCAP_CFLAGS], [PCAP C compiler flags])

PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log], [have_libnetfilter_log=yes], [AC_MSG_ERROR([pkg-config cannot find libnetfilter_log])])
PKG_CHECK_MODULES([LIBNL], [libnl-3.0], [have_libnl=yes], [AC_MSG_ERROR([pkg-config cannot find libnl-3.0])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
