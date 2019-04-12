include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/autosrc.ami

include $(top_srcdir)/autosrc/Makefile.ami

bin_PROGRAMS=extractaudio
noinst_PROGRAMS=extractaudio_debug

MAINSRCDIR=$(top_srcdir)/src
extractaudio_SOURCES=extractaudio.c decoder.c rtpp_loader.c ${MAINSRCDIR}/rtp.c \
  ${MAINSRCDIR}/rtp_analyze.c ${MAINSRCDIR}/rtpp_util.c ${MAINSRCDIR}/rtpp_time.c \
  decoder.h format_au.h g711.h rtpp_loader.h \
  session.h g729_compat.c g729_compat.h ${MAINSRCDIR}/rtpp_network.c \
  ${MAINSRCDIR}/rtpp_mallocs.c \
  ${MAINSRCDIR}/rtpp_refcnt.c $(rtpp_refcnt_AUTOSRCS) \
  ${MAINSRCDIR}/rtpp_ringbuf.c $(rtpp_ringbuf_AUTOSRCS) \
  ${MAINSRCDIR}/rtpp_netaddr.c ${MAINSRCDIR}/rtpp_netaddr.h \
  $(rtpp_netaddr_AUTOSRCS) eaud_oformats.c eaud_oformats.h rtpp_scan_pcap.c rtpp_scan_pcap.h \
  eaud_pcap.c eaud_pcap.h eaud_substreams.c eaud_substreams.h
extractaudio_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@ @LIBS_SNDFILE@ -lm -lpthread
extractaudio_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR)
if BUILD_CRYPTO
extractaudio_SOURCES+=eaud_crypto.c eaud_crypto.h srtp_util.c srtp_util.h
extractaudio_LDADD+=@LIBS_SRTP@
endif

extractaudio_debug_SOURCES = $(extractaudio_SOURCES) $(RTPP_MEMDEB_CORESRCS)
extractaudio_debug_LDADD = $(extractaudio_LDADD) $(RTPP_MEMDEB_LDADD)
extractaudio_debug_CPPFLAGS = $(extractaudio_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=extractaudio
extractaudio_debug_CFLAGS = $(RTPP_MEMDEB_CFLAGS)

DEFS=   -DWITHOUT_RTPPLOG -Wall @DEFS@
