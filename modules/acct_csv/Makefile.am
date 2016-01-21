pkglib_LTLIBRARIES = rtpp_csv_acct.la rtpp_csv_acct_debug.la

rtpp_csv_acct_la_SOURCES = rtpp_csv_acct.c
rtpp_csv_acct_la_LDFLAGS = -avoid-version -module -shared -export-dynamic

rtpp_csv_acct_debug_la_SOURCES = ${rtpp_csv_acct_la_SOURCES}
rtpp_csv_acct_debug_la_LIBADD=$(top_srcdir)/libexecinfo/libexecinfo.a \
  @LIBS_DL@
rtpp_csv_acct_debug_la_LDFLAGS=${rtpp_csv_acct_la_LDFLAGS}
rtpp_csv_acct_debug_la_CPPFLAGS=-DRTPP_DEBUG
rtpp_csv_acct_debug_la_CFLAGS=-g3 -O0 -fno-omit-frame-pointer
