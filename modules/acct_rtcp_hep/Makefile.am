HEPSRCDIR=$(top_srcdir)/hepconnector

pkglib_LTLIBRARIES = rtpp_acct_rtcp_hep.la rtpp_acct_rtcp_hep_debug.la

rtpp_acct_rtcp_hep_la_SOURCES = rtpp_acct_rtcp_hep.c ${HEPSRCDIR}/core_hep.c
rtpp_acct_rtcp_hep_la_LDFLAGS = -avoid-version -module -shared -export-dynamic

rtpp_acct_rtcp_hep_debug_la_SOURCES = ${rtpp_acct_rtcp_hep_la_SOURCES}
rtpp_acct_rtcp_hep_debug_la_LIBADD=$(top_srcdir)/libexecinfo/libexecinfo.a \
  @LIBS_DL@
rtpp_acct_rtcp_hep_debug_la_LDFLAGS=${rtpp_acct_rtcp_hep_la_LDFLAGS}
rtpp_acct_rtcp_hep_debug_la_CPPFLAGS=-DRTPP_DEBUG
rtpp_acct_rtcp_hep_debug_la_CFLAGS=-g3 -O0 -fno-omit-frame-pointer

DEFS=	-Wall -DRTPP_MODULE -Dmalloc=mod_malloc -Dfree=mod_free -Drealloc=mod_realloc @DEFS@ -I${HEPSRCDIR}
