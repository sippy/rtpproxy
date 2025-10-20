include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/autosrc/Makefile.ami

bin_PROGRAMS=makeann
if ENABLE_noinst
if ENABLE_debug
noinst_PROGRAMS=makeann_debug
endif
endif

extractaudio_SRCDIR=$(top_srcdir)/extractaudio

makeann_SOURCES=makeann.c rtp.h g711.h $(extractaudio_SRCDIR)/g729_compat.c \
  $(extractaudio_SRCDIR)/g729_compat.h
makeann_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@
makeann_CPPFLAGS=-I$(extractaudio_SRCDIR) -D_BSD_SOURCE
makeann_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG)
makeann_LDFLAGS = $(LTO_FLAG)

makeann_debug_SOURCES = $(makeann_SOURCES) $(RTPP_MEMDEB_CORESRCS) $(rtpp_refcnt_AUTOSRCS)
makeann_debug_LDADD = $(makeann_LDADD) $(RTPP_MEMDEB_LDADD)
makeann_debug_CPPFLAGS = $(makeann_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=makeann
makeann_debug_CFLAGS = $(NOPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)
makeann_debug_LDFLAGS = $(makeann_LDFLAGS)

DEFS=	-Wall @DEFS@
