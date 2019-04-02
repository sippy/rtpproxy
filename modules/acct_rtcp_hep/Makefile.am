include $(top_srcdir)/m4/memdeb.ami

HEPSRCDIR=$(top_srcdir)/hepconnector
UCLSRCDIR=$(top_srcdir)/external/libucl

pkglib_LTLIBRARIES = rtpp_acct_rtcp_hep.la rtpp_acct_rtcp_hep_debug.la

noinst_PROGRAMS = rtcp2json_test
rtcp2json_test_SOURCES = rtcp2json_test.c rtpp_sbuf.c rtcp2json.c
rtcp2json_test_CFLAGS = $(AM_CFLAGS)

rtpp_acct_rtcp_hep_la_SOURCES = rtpp_acct_rtcp_hep.c rtcp2json.c rtpp_sbuf.c \
  $(HEPSRCDIR)/core_hep.c rtpp_arh_conf.c
rtpp_acct_rtcp_hep_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
rtpp_acct_rtcp_hep_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -I$(HEPSRCDIR) -I$(UCLSRCDIR)/include
rtpp_acct_rtcp_hep_la_CFLAGS=-std=c11 -D_XOPEN_SOURCE
#rtpp_acct_rtcp_hep_la_LIBADD = -lz

rtpp_acct_rtcp_hep_debug_la_SOURCES = $(rtpp_acct_rtcp_hep_la_SOURCES)
rtpp_acct_rtcp_hep_debug_la_LIBADD = $(rtpp_acct_rtcp_hep_la_LIBADD) $(RTPP_MEMDEB_LDADD)
rtpp_acct_rtcp_hep_debug_la_LDFLAGS=$(rtpp_acct_rtcp_hep_la_LDFLAGS)
rtpp_acct_rtcp_hep_debug_la_CPPFLAGS=$(rtpp_acct_rtcp_hep_la_CPPFLAGS) -DRTPP_DEBUG
rtpp_acct_rtcp_hep_debug_la_CFLAGS=$(RTPP_MEMDEB_CFLAGS) -std=c11 -D_XOPEN_SOURCE

DEFS=	-Wall @DEFS@

noinst_PROGRAMS += rtpp_sbuf_selftest
rtpp_sbuf_selftest_CPPFLAGS = -Drtpp_sbuf_selftest=main \
  $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpp_sbuf
rtpp_sbuf_selftest_CFLAGS = $(RTPP_MEMDEB_CFLAGS)
rtpp_sbuf_selftest_SOURCES = rtpp_sbuf.c rtpp_sbuf.h \
  $(RTPP_MEMDEB_CORESRCS)
rtpp_sbuf_selftest_LDADD = $(RTPP_MEMDEB_LDADD)
