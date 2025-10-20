include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

HEPSRCDIR=$(top_srcdir)/external/hepconnector
UCLSRCDIR=$(top_srcdir)/external/libucl

pkglib_LTLIBRARIES = rtpp_acct_rtcp_hep.la

noinst_LTLIBRARIES = librtpp_acct_rtcp_hep.la

if ENABLE_noinst
noinst_PROGRAMS = rtcp2json_test
endif
if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_acct_rtcp_hep_debug.la
endif

rtcp2json_test_SOURCES = rtcp2json_test.c $(MAINSRCDIR)/rtpp_sbuf.c rtcp2json.c
rtcp2json_test_CFLAGS = $(OPT_CFLAGS) $(AM_CFLAGS) $(LTO_FLAG)
rtcp2json_test_LDFLAGS = $(AM_CFLAGS) $(LTO_FLAG)

rtpp_acct_rtcp_hep_la_SOURCES = rtpp_acct_rtcp_hep.c rtcp2json.c \
  $(HEPSRCDIR)/core_hep.c rtpp_arh_conf.c
rtpp_acct_rtcp_hep_la_LDFLAGS = -avoid-version -module -shared \
  $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_acct_rtcp_hep_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -I$(HEPSRCDIR) -I$(UCLSRCDIR)/include \
  -DRTPP_MOD_NAME="acct_rtcp_hep"
CFLAGS_acct_rtcp_hep_common = -std=c11 -D_BSD_SOURCE -D_XOPEN_SOURCE \
  $(LTO_FLAG)
rtpp_acct_rtcp_hep_la_CFLAGS=$(OPT_CFLAGS) $(CFLAGS_acct_rtcp_hep_common)

rtpp_acct_rtcp_hep_debug_la_SOURCES = $(rtpp_acct_rtcp_hep_la_SOURCES)
rtpp_acct_rtcp_hep_debug_la_LIBADD = $(RTPP_MEMDEB_LDADD)
rtpp_acct_rtcp_hep_debug_la_LDFLAGS=$(rtpp_acct_rtcp_hep_la_LDFLAGS)
rtpp_acct_rtcp_hep_debug_la_CPPFLAGS=$(rtpp_acct_rtcp_hep_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="acct_rtcp_hep"
rtpp_acct_rtcp_hep_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_acct_rtcp_hep_common) \
 $(RTPP_MEMDEB_CFLAGS)

if ENABLE_noinst
noinst_PROGRAMS += rtpp_sbuf_selftest
endif
rtpp_sbuf_selftest_CPPFLAGS = -Drtpp_sbuf_selftest=main \
  $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpp_sbuf
rtpp_sbuf_selftest_CFLAGS = $(OPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG)
rtpp_sbuf_selftest_SOURCES = $(MAINSRCDIR)/rtpp_sbuf.c $(MAINSRCDIR)/rtpp_sbuf.h \
  $(RTPP_MEMDEB_CORESRCS) $(rtpp_refcnt_AUTOSRCS)
rtpp_sbuf_selftest_LDADD = $(RTPP_MEMDEB_LDADD)
rtpp_sbuf_selftest_LDFLAGS = $(LTO_FLAG)

librtpp_acct_rtcp_hep_la_SOURCES = $(rtpp_acct_rtcp_hep_la_SOURCES)
librtpp_acct_rtcp_hep_la_CPPFLAGS = $(rtpp_acct_rtcp_hep_la_CPPFLAGS) -DLIBRTPPROXY
librtpp_acct_rtcp_hep_la_CFLAGS = $(rtpp_acct_rtcp_hep_la_CFLAGS)
