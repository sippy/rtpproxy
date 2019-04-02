include $(top_srcdir)/m4/memdeb.ami

pkglib_LTLIBRARIES = rtpp_acct_csv.la rtpp_acct_csv_debug.la

rtpp_acct_csv_la_SOURCES = rtpp_acct_csv.c
rtpp_acct_csv_la_LDFLAGS = -avoid-version -module -shared -export-dynamic

rtpp_acct_csv_debug_la_SOURCES = ${rtpp_acct_csv_la_SOURCES}
rtpp_acct_csv_debug_la_LIBADD = $(RTPP_MEMDEB_LDADD)
rtpp_acct_csv_debug_la_LDFLAGS=${rtpp_acct_csv_la_LDFLAGS}
rtpp_acct_csv_debug_la_CPPFLAGS=-DRTPP_DEBUG
rtpp_acct_csv_debug_la_CFLAGS=$(RTPP_MEMDEB_CFLAGS)

DEFS=	-Wall @DEFS@
