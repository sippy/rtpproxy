include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/autosrc/Makefile.ami

UCL_DIR=$(top_srcdir)/external/libucl
UCL_SDIR=$(UCL_DIR)/src

noinst_LTLIBRARIES = libucl.la

libucl_la_SOURCES = $(UCL_SDIR)/ucl_emitter_streamline.c \
  $(UCL_SDIR)/ucl_emitter_utils.c \
  $(UCL_SDIR)/ucl_emitter.c \
  $(UCL_SDIR)/ucl_hash.c \
  $(UCL_SDIR)/ucl_msgpack.c \
  $(UCL_SDIR)/ucl_parser.c \
  $(UCL_SDIR)/ucl_schema.c \
  $(UCL_SDIR)/ucl_sexp.c \
  $(UCL_SDIR)/ucl_util.c
CFLAGS_libucl_common = -Wno-pointer-sign -std=c11 -DHAVE_CONFIG_H -D_BSD_SOURCE \
  -I$(UCL_DIR)/include \
  -I$(UCL_DIR)/uthash \
  -I$(UCL_DIR)/klib \
  -I$(UCL_DIR)/src/ \
  -Wno-unused-parameter $(LTO_FLAG)
libucl_la_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_libucl_common)
libucl_debug_la_SOURCES = $(libucl_la_SOURCES)
libucl_debug_la_CPPFLAGS = -DRTPP_MEMDEB_FREE_NULL $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpproxy
libucl_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_libucl_common) $(RTPP_MEMDEB_CFLAGS)

HEPSRCDIR=$(top_srcdir)/external/hepconnector

if ENABLE_noinst
noinst_PROGRAMS = libucl_test
endif
libucl_test_CPPFLAGS = -DMODULE_IF_CODE -Dmod_strdup=strdup -Dmod_free=free \
  $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=libucl_test \
  -I$(UCL_DIR)/include -I$(HEPSRCDIR)
libucl_test_CFLAGS = $(OPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS) $(LTO_FLAG)
libucl_test_SOURCES = libucl_test.c \
  $(top_srcdir)/modules/acct_rtcp_hep/rtpp_arh_conf.c \
  $(MAINSRCDIR)/rtpp_ucl.c $(RTPP_MEMDEB_CORESRCS) $(rtpp_refcnt_AUTOSRCS)
libucl_test_LDADD=$(RTPP_MEMDEB_LDADD)
libucl_test_LDLAGS=$(LTO_FLAG)

if ENABLE_debug
noinst_LTLIBRARIES += libucl_debug.la
libucl_test_LDADD += libucl_debug.la
else
libucl_test_LDADD += libucl.la
endif
