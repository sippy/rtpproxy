pkglib_LTLIBRARIES = rtpp_acct_csv.la rtpp_acct_csv_debug.la

rtpp_acct_csv_la_SOURCES = rtpp_acct_csv.c
rtpp_acct_csv_la_LDFLAGS = -avoid-version -module -shared -export-dynamic

rtpp_acct_csv_debug_la_SOURCES = ${rtpp_acct_csv_la_SOURCES}
rtpp_acct_csv_debug_la_LIBADD=$(top_srcdir)/libexecinfo/libexecinfo.a \
  @LIBS_DL@
rtpp_acct_csv_debug_la_LDFLAGS=${rtpp_acct_csv_la_LDFLAGS}
rtpp_acct_csv_debug_la_CPPFLAGS=-DRTPP_DEBUG
rtpp_acct_csv_debug_la_CFLAGS=-g3 -O0 -fno-omit-frame-pointer

DEFS=	-Wall @DEFS@
