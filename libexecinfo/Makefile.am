noinst_LIBRARIES = libexecinfo.a
libexecinfo_a_SOURCES = execinfo.c execinfo.h stacktraverse.c stacktraverse.h
libexecinfo_a_CFLAGS = -g3 -O0 -fno-omit-frame-pointer

noinst_PROGRAMS = execinfo_test
execinfo_test_CPPFLAGS = -DRTPP_MEMDEB_STDOUT -DMEMDEB_APP=execinfo_test \
  -Werror=implicit-function-declaration -Wall
execinfo_test_SOURCES = execinfo_test.c execinfo_testfunc.c execinfo_testfunc1.c
execinfo_test_LDADD = libexecinfo.a
execinfo_test_CFLAGS = -g3 -O0 -fno-omit-frame-pointer
