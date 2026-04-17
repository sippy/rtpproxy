include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

RTQ_DIR=$(top_srcdir)/external/RTQueue
RTQ_SDIR=$(RTQ_DIR)/src

noinst_LTLIBRARIES = libRTQueue.la

CFLAGS_libRTQueue_common = -std=c11 -DHAVE_CONFIG_H -D_BSD_SOURCE \
  $(LTO_FLAG)
libRTQueue_la_SOURCES = $(RTQ_SDIR)/SPMCQueue.c $(RTQ_SDIR)/SPMCQueue.h
libRTQueue_la_CFLAGS = $(OPT_CFLAGS) -DNDEBUG $(CFLAGS_libRTQueue_common)

if ENABLE_debug
noinst_LTLIBRARIES += libRTQueue_debug.la
libRTQueue_debug_la_SOURCES = $(libRTQueue_la_SOURCES)
libRTQueue_debug_la_CPPFLAGS = -DRTPP_MEMDEB_FREE_NULL -DMEMDEB_APP=rtpproxy \
  $(RTPP_MEMDEB_CPPFLAGS)
libRTQueue_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_libRTQueue_common) \
  $(RTPP_MEMDEB_CFLAGS)
endif
