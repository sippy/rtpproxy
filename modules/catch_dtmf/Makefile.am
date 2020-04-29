include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami

pkglib_LTLIBRARIES = rtpp_catch_dtmf.la rtpp_catch_dtmf_debug.la

rtpp_catch_dtmf_la_SOURCES = rtpp_catch_dtmf.c
rtpp_catch_dtmf_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
rtpp_catch_dtmf_la_CPPFLAGS = -DRTPP_MODULE -Dmalloc=mod_malloc \
  -Dfree=mod_free -Drealloc=mod_realloc -I$(UCLSRCDIR)/include
rtpp_catch_dtmf_la_CFLAGS=-std=c11 -D_BSD_SOURCE -D_XOPEN_SOURCE
#rtpp_catch_dtmf_la_LIBADD = -lz

rtpp_catch_dtmf_debug_la_SOURCES = $(rtpp_catch_dtmf_la_SOURCES)
rtpp_catch_dtmf_debug_la_LIBADD = $(rtpp_catch_dtmf_la_LIBADD) $(RTPP_MEMDEB_LDADD)
rtpp_catch_dtmf_debug_la_LDFLAGS = $(rtpp_catch_dtmf_la_LDFLAGS)
rtpp_catch_dtmf_debug_la_CPPFLAGS = $(rtpp_catch_dtmf_la_CPPFLAGS) -DRTPP_DEBUG \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="catch_dtmf"
rtpp_catch_dtmf_debug_la_CFLAGS = $(RTPP_MEMDEB_CFLAGS) $(rtpp_catch_dtmf_la_CFLAGS)

DEFS=	$(CC_WFLAGS) @DEFS@
