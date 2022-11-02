include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

noinst_LIBRARIES = libexecinfo.a
libexecinfo_a_SOURCES = execinfo.c execinfo.h stacktraverse.c stacktraverse.h
libexecinfo_a_CFLAGS = $(NOPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG) -Wno-frame-address

noinst_PROGRAMS = execinfo_check execinfo_TEST
execinfo_check_CPPFLAGS = -Werror=implicit-function-declaration -Wall
execinfo_check_SOURCES = execinfo_check.c execinfo_testfunc.c execinfo_testfunc1.c
execinfo_check_LDADD = libexecinfo.a @LIBS_DL@ -lpthread
execinfo_check_CFLAGS = $(libexecinfo_a_CFLAGS)
execinfo_check_LDFLAGS = $(LTO_FLAG)

execinfo_TEST_CPPFLAGS = ${execinfo_check_CPPFLAGS} -Dexecinfo_TEST=main
execinfo_TEST_SOURCES = execinfo.c stacktraverse.c
execinfo_TEST_LDADD = @LIBS_DL@
execinfo_TEST_CFLAGS = $(OPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG)
execinfo_TEST_LDFLAGS = $(LTO_FLAG)
