include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/autosrc/Makefile.ami

RE_DIR=$(top_srcdir)/external/libre
RE_SDIR=$(RE_DIR)/src

noinst_LTLIBRARIES = libre.la

libre_la_SOURCES = $(RE_SDIR)/stun/stun.c $(RE_SDIR)/stun/stun.h \
  $(RE_SDIR)/stun/ctrans.c $(RE_SDIR)/stun/msg.c $(RE_SDIR)/stun/hdr.c \
  $(RE_SDIR)/stun/rep.c $(RE_SDIR)/stun/attr.c $(RE_SDIR)/stun/addr.c \
  $(RE_SDIR)/ice/cand.c $(RE_SDIR)/hmac/hmac_sha1.c $(RE_SDIR)/sa/sa.c \
  $(RE_SDIR)/ice/stunsrv.c $(RE_SDIR)/ice/stunsrv.h $(RE_SDIR)/ice/candpair.c \
  $(RE_SDIR)/ice/util.c $(RE_SDIR)/ice/comp.c $(RE_SDIR)/ice/icestr.c \
  $(RE_SDIR)/ice/icem.c $(RE_SDIR)/ice/icesdp.c \
  $(RE_SDIR)/fmt/regex.c $(RE_SDIR)/fmt/pl.c $(RE_SDIR)/fmt/str.c \
  $(RE_SDIR)/fmt/print.c $(RE_SDIR)/fmt/str_error.c \
  $(RE_SDIR)/sys/rand.c $(RE_SDIR)/mbuf/mbuf.c $(RE_SDIR)/net/netstr.c \
  $(RE_SDIR)/crc32/crc32.c $(RE_SDIR)/list/list.c $(RE_SDIR)/sys/endian.c \
  $(RE_SDIR)/sa/ntop.c $(RE_SDIR)/sa/pton.c rtpp_re.c rtpp_re_icesdp.c \
  rtpp_re_dbg.c rtpp_re.h rtpp_re_stub.c
CFLAGS_libre_common = -Wno-pointer-sign -std=c11 -DHAVE_CONFIG_H -D_BSD_SOURCE \
  -Wno-unused-parameter $(LTO_FLAG)
CPPFLAGS_libre_common = -I$(RE_DIR)/include -I$(RE_SDIR) \
  --include $(top_srcdir)/src/config.h --include rtpp_re.h \
  -DUSE_OPENSSL
libre_la_CFLAGS = $(OPT_CFLAGS) $(CFLAGS_libre_common)
libre_la_CPPFLAGS = $(CPPFLAGS_libre_common)
libre_la_LIBADD = $(LIB_CRYPTO)
libre_debug_la_SOURCES = $(libre_la_SOURCES)
libre_debug_la_CPPFLAGS = $(CPPFLAGS_libre_common) -DRTPP_MEMDEB_FREE_NULL \
  $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=libre
libre_debug_la_CFLAGS = $(NOPT_CFLAGS) $(CFLAGS_libre_common) $(RTPP_MEMDEB_CFLAGS)
libre_debug_la_LIBADD = $(libre_la_LIBADD)

if ENABLE_noinst
noinst_PROGRAMS = libre_test
endif

libre_test_CPPFLAGS = -DMODULE_IF_CODE -Dmod_strdup=strdup \
  $(CPPFLAGS_libre_common)
libre_test_CFLAGS = $(LTO_FLAG)
libre_test_SOURCES = libre_test.c
libre_test_LDLAGS = $(LTO_FLAG)

if ENABLE_debug
noinst_LTLIBRARIES += libre_debug.la
libre_test_CPPFLAGS += $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=libre_test
libre_test_SOURCES += $(RTPP_MEMDEB_CORESRCS) $(rtpp_refcnt_AUTOSRCS)
libre_test_CFLAGS += $(NOPT_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
libre_test_LDADD = $(RTPP_MEMDEB_LDADD) libre_debug.la
else
libre_test_CPPFLAGS += -I$(RTPP_AUTOSRC_DIR)
libre_test_SOURCES += $(top_srcdir)/src/rtpp_mallocs.c \
  $(top_srcdir)/src/rtpp_refcnt.c
libre_test_LDADD = libre.la
endif
