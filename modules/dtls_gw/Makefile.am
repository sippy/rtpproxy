include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

pkglib_LTLIBRARIES = rtpp_dtls_gw.la

if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_dtls_gw_debug.la
endif

noinst_LTLIBRARIES = librtpp_dtls_gw.la

rtpp_dtls_gw_la_SOURCES = rtpp_dtls_gw.c rtpp_dtls.c rtpp_dtls.h \
  rtpp_dtls_conn.c rtpp_dtls_conn.h rtpp_dtls_util.c rtpp_dtls_util.h
rtpp_dtls_gw_la_LDFLAGS = -avoid-version -module -shared $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_dtls_gw_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -DRTPP_MOD_NAME="dtls_gw"
CFLAGS_rtpp_dtls_gw_common = -std=c11 -D_BSD_SOURCE -D_XOPEN_SOURCE $(LTO_FLAG)
rtpp_dtls_gw_la_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_rtpp_dtls_gw_common)
rtpp_dtls_gw_la_LIBADD = $(LIB_SSL) $(LIBS_SRTP)

rtpp_dtls_gw_debug_la_SOURCES = $(rtpp_dtls_gw_la_SOURCES)
rtpp_dtls_gw_debug_la_LIBADD = $(rtpp_dtls_gw_la_LIBADD) $(RTPP_MEMDEB_LDADD)
rtpp_dtls_gw_debug_la_LDFLAGS = $(rtpp_dtls_gw_la_LDFLAGS)
rtpp_dtls_gw_debug_la_CPPFLAGS = $(rtpp_dtls_gw_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="dtls_gw"
rtpp_dtls_gw_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_rtpp_dtls_gw_common) \
 $(RTPP_MEMDEB_CFLAGS)

librtpp_dtls_gw_la_SOURCES = $(rtpp_dtls_gw_la_SOURCES)
librtpp_dtls_gw_la_CPPFLAGS = $(rtpp_dtls_gw_la_CPPFLAGS) -DLIBRTPPROXY
librtpp_dtls_gw_la_CFLAGS = $(rtpp_dtls_gw_la_CFLAGS)
librtpp_dtls_gw_la_LIBADD = $(rtpp_dtls_gw_la_LIBADD)

include $(top_srcdir)/m4/ipolice.ami
