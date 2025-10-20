include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

include $(top_srcdir)/autosrc/Makefile.ami

bin_PROGRAMS=extractaudio
if ENABLE_noinst
if ENABLE_debug
noinst_PROGRAMS=extractaudio_debug
endif
endif

extractaudio_BASESOURCES=extractaudio.c decoder.c rtpp_loader.c $(MAINSRCDIR)/rtp.c \
  $(MAINSRCDIR)/rtp_analyze.c $(MAINSRCDIR)/rtpp_util.c $(MAINSRCDIR)/rtpp_time.c \
  decoder.h format_au.h g711.h rtpp_loader.h \
  session.h g729_compat.c g729_compat.h $(MAINSRCDIR)/rtpp_network.c \
  $(MAINSRCDIR)/rtpp_ringbuf.c \
  $(MAINSRCDIR)/rtpp_netaddr.c $(MAINSRCDIR)/rtpp_netaddr.h \
  eaud_oformats.c eaud_oformats.h rtpp_scan_pcap.c rtpp_scan_pcap.h \
  eaud_pcap.c eaud_pcap.h eaud_substreams.c eaud_substreams.h \
  rtpp_scan_adhoc.c rtpp_scan_adhoc.h eaud_adhoc.c eaud_adhoc.h
extractaudio_SOURCES=$(extractaudio_BASESOURCES) $(MAINSRCDIR)/rtpp_mallocs.c \
  $(MAINSRCDIR)/rtpp_mallocs.h $(MAINSRCDIR)/rtpp_refcnt.c $(MAINSRCDIR)/rtpp_refcnt.h
extractaudio_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@ @LIBS_SNDFILE@ -lm -lpthread
extractaudio_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR) -D_BSD_SOURCE
if BUILD_CRYPTO
extractaudio_BASESOURCES+=eaud_crypto.c eaud_crypto.h srtp_util.c srtp_util.h
extractaudio_LDADD+=@LIBS_SRTP@
endif
extractaudio_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG)
extractaudio_LDFLAGS = $(LTO_FLAG)

extractaudio_debug_SOURCES = $(extractaudio_BASESOURCES) $(RTPP_MEMDEB_CORESRCS) \
  $(rtpp_netaddr_AUTOSRCS) $(rtpp_refcnt_AUTOSRCS) $(rtpp_ringbuf_AUTOSRCS)
extractaudio_debug_LDADD = $(extractaudio_LDADD) $(RTPP_MEMDEB_LDADD)
extractaudio_debug_CPPFLAGS = $(extractaudio_CPPFLAGS) \
  $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=extractaudio
extractaudio_debug_CFLAGS = $(NOPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)
extractaudio_debug_LDFLAGS = $(extractaudio_LDFLAGS)

DEFS=   -DWITHOUT_RTPPLOG $(CC_WFLAGS) @DEFS@
