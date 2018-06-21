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
#rtpp_acct_rtcp_hep_la_LIBADD = -lz

rtpp_acct_rtcp_hep_debug_la_SOURCES = $(rtpp_acct_rtcp_hep_la_SOURCES)
rtpp_acct_rtcp_hep_debug_la_LIBADD=$(top_srcdir)/libexecinfo/libexecinfo.a \
  @LIBS_DL@ $(rtpp_acct_rtcp_hep_la_LIBADD)
rtpp_acct_rtcp_hep_debug_la_LDFLAGS=$(rtpp_acct_rtcp_hep_la_LDFLAGS)
rtpp_acct_rtcp_hep_debug_la_CPPFLAGS=$(rtpp_acct_rtcp_hep_la_CPPFLAGS) -DRTPP_DEBUG
rtpp_acct_rtcp_hep_debug_la_CFLAGS=-g3 -O0 -fno-omit-frame-pointer

DEFS=	-Wall @DEFS@
