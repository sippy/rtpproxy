include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

if ENABLE_LIBUNWIND
CPPFLAGS_UNWIND = -DUSE_LIBUNWIND
STR_SOURCE = execinfo_luw.c
else
STR_SOURCE = stacktraverse.c
endif

noinst_LTLIBRARIES = libexecinfo.la
libexecinfo_la_SOURCES = execinfo.c execinfo.h stacktraverse.h \
 execinfo_internal.h ${STR_SOURCE}
libexecinfo_la_CFLAGS = $(NOPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG)
libexecinfo_la_CPPFLAGS = $(NOPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG) $(CPPFLAGS_UNWIND)
libexecinfo_la_LIBADD = @LIBS_UNWIND@

if ENABLE_noinst
noinst_PROGRAMS = execinfo_check execinfo_TEST
endif
execinfo_check_CPPFLAGS = -Werror=implicit-function-declaration -Wall $(CPPFLAGS_UNWIND)
execinfo_check_SOURCES = execinfo_check.c execinfo_testfunc.c execinfo_testfunc1.c
execinfo_check_CFLAGS = $(libexecinfo_la_CFLAGS)
execinfo_check_LDADD = libexecinfo.la @LIBS_DL@ @LIBS_UNWIND@ -lpthread
execinfo_check_LDFLAGS = $(LTO_FLAG)

execinfo_TEST_CPPFLAGS = ${execinfo_check_CPPFLAGS} -Dexecinfo_TEST=main $(CPPFLAGS_UNWIND)
execinfo_TEST_SOURCES = execinfo.c ${STR_SOURCE}
execinfo_TEST_CFLAGS = $(OPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG)
execinfo_TEST_LDADD = @LIBS_DL@ @LIBS_UNWIND@
execinfo_TEST_LDFLAGS = $(LTO_FLAG)
