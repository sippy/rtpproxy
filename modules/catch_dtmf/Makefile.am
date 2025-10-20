include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

pkglib_LTLIBRARIES = rtpp_catch_dtmf.la

if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_catch_dtmf_debug.la
endif

noinst_LTLIBRARIES = librtpp_catch_dtmf.la

rtpp_catch_dtmf_la_SOURCES = rtpp_catch_dtmf.c
rtpp_catch_dtmf_la_LDFLAGS = -avoid-version -module -shared $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_catch_dtmf_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -DRTPP_MOD_NAME="catch_dtmf"
CFLAGS_rtpp_catch_dtmf_common = -std=c11 -D_BSD_SOURCE -D_XOPEN_SOURCE $(LTO_FLAG)
rtpp_catch_dtmf_la_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_rtpp_catch_dtmf_common)

rtpp_catch_dtmf_debug_la_SOURCES = $(rtpp_catch_dtmf_la_SOURCES)
rtpp_catch_dtmf_debug_la_LIBADD = $(rtpp_catch_dtmf_la_LIBADD) $(RTPP_MEMDEB_LDADD)
rtpp_catch_dtmf_debug_la_LDFLAGS = $(rtpp_catch_dtmf_la_LDFLAGS)
rtpp_catch_dtmf_debug_la_CPPFLAGS = $(rtpp_catch_dtmf_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="catch_dtmf"
rtpp_catch_dtmf_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_rtpp_catch_dtmf_common) \
 $(RTPP_MEMDEB_CFLAGS)

librtpp_catch_dtmf_la_SOURCES = $(rtpp_catch_dtmf_la_SOURCES)
librtpp_catch_dtmf_la_CPPFLAGS = $(rtpp_catch_dtmf_la_CPPFLAGS) -DLIBRTPPROXY
librtpp_catch_dtmf_la_CFLAGS = $(rtpp_catch_dtmf_la_CFLAGS)
