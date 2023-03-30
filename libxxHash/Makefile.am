include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

XXH_DIR=$(top_srcdir)/external/xxHash
XXH_SDIR=$(XXH_DIR)

noinst_LIBRARIES = libxxHash.a libxxHash_debug.a
libxxHash_a_SOURCES = $(XXH_SDIR)/xxhash.c $(XXH_SDIR)/xxhash.h
CFLAGS_libxxHash_common = -Wno-pointer-sign -std=c11 -DHAVE_CONFIG_H -D_BSD_SOURCE \
  -Wno-unused-parameter $(LTO_FLAG)
libxxHash_a_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_libxxHash_common)
libxxHash_debug_a_SOURCES = $(libxxHash_a_SOURCES)
libxxHash_debug_a_CPPFLAGS = -DRTPP_MEMDEB_FREE_NULL $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpproxy
libxxHash_debug_a_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_libxxHash_common) $(RTPP_MEMDEB_CFLAGS)
