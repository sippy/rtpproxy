include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

pkglib_LTLIBRARIES = rtpp_ice_lite.la

if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_ice_lite_debug.la
endif

noinst_LTLIBRARIES = librtpp_ice_lite.la

rtpp_ice_lite_la_SOURCES = rtpp_ice_lite.c
rtpp_ice_lite_la_LDFLAGS = -avoid-version -module -shared $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_ice_lite_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -DRTPP_MOD_NAME="ice_lite" \
  -I$(top_srcdir)/external/libre/include -I$(top_srcdir)/external/libre/src \
  -I$(top_srcdir)/libre
CFLAGS_rtpp_ice_lite_common = -std=c11 -D_BSD_SOURCE -D_XOPEN_SOURCE $(LTO_FLAG)
rtpp_ice_lite_la_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_rtpp_ice_lite_common)
rtpp_ice_lite_la_LIBADD = $(top_srcdir)/libre/libre.la $(LIB_CRYPTO)

rtpp_ice_lite_debug_la_SOURCES = $(rtpp_ice_lite_la_SOURCES)
rtpp_ice_lite_debug_la_LIBADD = $(top_srcdir)/libre/libre_debug.la $(RTPP_MEMDEB_LDADD) $(LIB_CRYPTO)
rtpp_ice_lite_debug_la_LDFLAGS = $(rtpp_ice_lite_la_LDFLAGS)
rtpp_ice_lite_debug_la_CPPFLAGS = $(rtpp_ice_lite_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="ice_lite"
rtpp_ice_lite_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_rtpp_ice_lite_common) \
 $(RTPP_MEMDEB_CFLAGS)

librtpp_ice_lite_la_SOURCES = $(rtpp_ice_lite_la_SOURCES)
librtpp_ice_lite_la_CPPFLAGS = $(rtpp_ice_lite_la_CPPFLAGS) -DLIBRTPPROXY
librtpp_ice_lite_la_CFLAGS = $(rtpp_ice_lite_la_CFLAGS)
librtpp_ice_lite_la_LIBADD = $(rtpp_ice_lite_la_LIBADD)
