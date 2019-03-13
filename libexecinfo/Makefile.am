noinst_LIBRARIES = libexecinfo.a
libexecinfo_a_SOURCES = execinfo.c execinfo.h stacktraverse.c stacktraverse.h
libexecinfo_a_CFLAGS = -g3 -O0 -fno-omit-frame-pointer

noinst_PROGRAMS = execinfo_test execinfo_TEST
execinfo_test_CPPFLAGS = -Werror=implicit-function-declaration -Wall
execinfo_test_SOURCES = execinfo_test.c execinfo_testfunc.c execinfo_testfunc1.c
execinfo_test_LDADD = libexecinfo.a @LIBS_DL@
execinfo_test_CFLAGS = -g3 -O0 -fno-omit-frame-pointer

execinfo_TEST_CPPFLAGS = ${execinfo_test_CPPFLAGS} -Dexecinfo_TEST=main
execinfo_TEST_SOURCES = execinfo.c stacktraverse.c
execinfo_TEST_LDADD = @LIBS_DL@
execinfo_TEST_CFLAGS = ${execinfo_test_CFLAGS}
