include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/m4/rtpp_module.ami

pkglib_LTLIBRARIES = rtpp_acct_csv.la

if ENABLE_debug
pkglib_LTLIBRARIES += rtpp_acct_csv_debug.la
endif

noinst_LTLIBRARIES = librtpp_acct_csv.la

rtpp_acct_csv_la_SOURCES = rtpp_acct_csv.c
rtpp_acct_csv_la_LDFLAGS = -avoid-version -module -shared $(LTO_FLAG) $(LDFLAG_SYMEXPORT)
rtpp_acct_csv_la_CPPFLAGS = -D_BSD_SOURCE -DRTPP_MOD_NAME="acct_csv"
rtpp_acct_csv_la_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG)

rtpp_acct_csv_debug_la_SOURCES = ${rtpp_acct_csv_la_SOURCES}
rtpp_acct_csv_debug_la_LIBADD = $(RTPP_MEMDEB_LDADD)
rtpp_acct_csv_debug_la_LDFLAGS=${rtpp_acct_csv_la_LDFLAGS}
rtpp_acct_csv_debug_la_CPPFLAGS=$(rtpp_acct_csv_la_CPPFLAGS) \
 $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP="acct_csv"
rtpp_acct_csv_debug_la_CFLAGS = $(NOPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)

librtpp_acct_csv_la_SOURCES = $(rtpp_acct_csv_la_SOURCES)
librtpp_acct_csv_la_CPPFLAGS = $(rtpp_acct_csv_la_CPPFLAGS) -DLIBRTPPROXY
librtpp_acct_csv_la_CFLAGS = $(rtpp_acct_csv_la_CFLAGS)
