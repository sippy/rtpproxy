include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

pkglib_LTLIBRARIES = rtpp_badmod1.la rtpp_badmod2.la \
 rtpp_badmod3.la rtpp_badmod4.la

if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_badmod1_debug.la \
 rtpp_badmod2_debug.la rtpp_badmod3_debug.la rtpp_badmod4_debug.la
endif

rtpp_badmod1_la_SOURCES = rtpp_badmod1.c
rtpp_badmod1_la_LDFLAGS = -avoid-version -module -shared $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_badmod1_la_CPPFLAGS = -D_BSD_SOURCE
rtpp_badmod1_la_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG)

rtpp_badmod1_debug_la_SOURCES = ${rtpp_badmod1_la_SOURCES}
rtpp_badmod1_debug_la_LIBADD = $(RTPP_MEMDEB_LDADD)
rtpp_badmod1_debug_la_LDFLAGS=${rtpp_badmod1_la_LDFLAGS}
rtpp_badmod1_debug_la_CPPFLAGS=$(rtpp_badmod1_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="badmod1"
rtpp_badmod1_debug_la_CFLAGS = $(NOPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)

rtpp_badmod2_la_SOURCES = rtpp_badmod2.c
rtpp_badmod2_la_LDFLAGS = $(rtpp_badmod1_la_LDFLAGS)
rtpp_badmod2_la_CPPFLAGS = $(rtpp_badmod1_la_CPPFLAGS)
rtpp_badmod2_la_CFLAGS = $(rtpp_badmod1_la_CFLAGS)

rtpp_badmod2_debug_la_SOURCES = ${rtpp_badmod2_la_SOURCES}
rtpp_badmod2_debug_la_LIBADD = $(rtpp_badmod1_debug_la_LIBADD)
rtpp_badmod2_debug_la_LDFLAGS=${rtpp_badmod1_la_LDFLAGS}
rtpp_badmod2_debug_la_CPPFLAGS=$(rtpp_badmod1_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="badmod2"
rtpp_badmod2_debug_la_CFLAGS = $(rtpp_badmod1_debug_la_CFLAGS)

rtpp_badmod3_la_SOURCES = rtpp_badmod3.c
rtpp_badmod3_la_LDFLAGS = $(rtpp_badmod1_la_LDFLAGS)
rtpp_badmod3_la_CPPFLAGS = $(rtpp_badmod1_la_CPPFLAGS)
rtpp_badmod3_la_CFLAGS = $(rtpp_badmod1_la_CFLAGS)

rtpp_badmod3_debug_la_SOURCES = ${rtpp_badmod3_la_SOURCES}
rtpp_badmod3_debug_la_LIBADD = $(rtpp_badmod1_debug_la_LIBADD)
rtpp_badmod3_debug_la_LDFLAGS=${rtpp_badmod1_la_LDFLAGS}
rtpp_badmod3_debug_la_CPPFLAGS=$(rtpp_badmod1_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="badmod3"
rtpp_badmod3_debug_la_CFLAGS = $(rtpp_badmod1_debug_la_CFLAGS)

rtpp_badmod4_la_SOURCES = rtpp_badmod4.c
rtpp_badmod4_la_LDFLAGS = $(rtpp_badmod1_la_LDFLAGS)
rtpp_badmod4_la_CPPFLAGS = $(rtpp_badmod1_la_CPPFLAGS)
rtpp_badmod4_la_CFLAGS = $(rtpp_badmod1_la_CFLAGS)

rtpp_badmod4_debug_la_SOURCES = ${rtpp_badmod4_la_SOURCES}
rtpp_badmod4_debug_la_LIBADD = $(rtpp_badmod1_debug_la_LIBADD)
rtpp_badmod4_debug_la_LDFLAGS=${rtpp_badmod1_la_LDFLAGS}
rtpp_badmod4_debug_la_CPPFLAGS=$(rtpp_badmod1_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="badmod4"
rtpp_badmod4_debug_la_CFLAGS = $(rtpp_badmod1_debug_la_CFLAGS)

install:
	true
