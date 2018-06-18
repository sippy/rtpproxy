UCL_DIR=$(top_srcdir)/external/libucl
UCL_SDIR=$(UCL_DIR)/src

noinst_LIBRARIES = libucl.a libucl_debug.a
libucl_a_SOURCES = $(UCL_SDIR)/ucl_emitter_streamline.c \
  $(UCL_SDIR)/ucl_emitter_utils.c \
  $(UCL_SDIR)/ucl_emitter.c \
  $(UCL_SDIR)/ucl_hash.c \
  $(UCL_SDIR)/ucl_msgpack.c \
  $(UCL_SDIR)/ucl_parser.c \
  $(UCL_SDIR)/ucl_schema.c \
  $(UCL_SDIR)/ucl_sexp.c \
  $(UCL_SDIR)/ucl_util.c
libucl_a_CFLAGS = -DHAVE_MATH_H -DHAVE_FLOAT_H -DHAVE_CTYPE_H -DHAVE_ERRNO_H \
  -DHAVE_SYS_MMAN_H -I$(UCL_DIR)/include \
  -I$(UCL_DIR)/uthash \
  -I$(UCL_DIR)/klib \
  -I$(UCL_DIR)/src/ \
  -Wno-unused-parameter
libucl_debug_a_SOURCES = $(libucl_a_SOURCES)
libucl_debug_a_CPPFLAGS = -DRTPP_MEMDEB_STDOUT -DMEMDEB_APP=rtpproxy -include $(top_srcdir)/src/rtpp_memdeb.h
libucl_debug_a_CFLAGS = $(libucl_a_CFLAGS)

noinst_PROGRAMS = libucl_test
libucl_test_CPPFLAGS = -DRTPP_MEMDEB_STDOUT -DMEMDEB_APP=rtpproxy
libucl_test_CFLAGS = -I$(UCL_DIR)/include
libucl_test_SOURCES = libucl_test.c \
  $(top_srcdir)/src/rtpp_memdeb.c
libucl_test_LDADD=libucl_debug.a
