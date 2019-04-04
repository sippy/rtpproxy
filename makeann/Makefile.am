include $(top_srcdir)/m4/memdeb.ami

bin_PROGRAMS=makeann
noinst_PROGRAMS=makeann_debug

extractaudio_SRCDIR=$(top_srcdir)/extractaudio

makeann_SOURCES=makeann.c rtp.h g711.h $(extractaudio_SRCDIR)/g729_compat.c \
  $(extractaudio_SRCDIR)/g729_compat.h
makeann_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@
makeann_CPPFLAGS=-I$(extractaudio_SRCDIR)

makeann_debug_SOURCES = $(makeann_SOURCES) $(RTPP_MEMDEB_CORESRCS)
makeann_debug_LDADD = $(makeann_LDADD) $(RTPP_MEMDEB_LDADD)
makeann_debug_CPPFLAGS = $(makeann_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=makeann
makeann_debug_CFLAGS = $(RTPP_MEMDEB_CFLAGS)


DEFS=	-Wall @DEFS@
