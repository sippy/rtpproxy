include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/autosrc.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

include $(top_srcdir)/autosrc/Makefile.ami

bin_PROGRAMS=extractaudio extractframes
noinst_PROGRAMS=extractaudio_debug

EAUD_COMSRCS = rtpp_loader.c rtpp_loader.h eaud_session.c eaud_session.h \
  rtpp_scan_pcap.c rtpp_scan_pcap.h rtpp_scan_adhoc.c rtpp_scan_adhoc.h \
  eaud_pcap.c eaud_pcap.h eaud_adhoc.c eaud_adhoc.h eaud_channels.c eaud_channels.h \
  ${MAINSRCDIR}/rtpp_mallocs.c ${MAINSRCDIR}/rtpp_refcnt.c $(rtpp_refcnt_AUTOSRCS) \
  ${MAINSRCDIR}/rtpp_ringbuf.c $(rtpp_ringbuf_AUTOSRCS) \
  ${MAINSRCDIR}/rtp.c ${MAINSRCDIR}/rtp_analyze.c

extractaudio_SOURCES = extractaudio.c $(EAUD_COMSRCS) decoder.c decoder.h \
  format_au.h g711.h g729_compat.c g729_compat.h \
  eaud_oformats.c eaud_oformats.h eaud_substreams.c eaud_substreams.h \
  ${MAINSRCDIR}/rtpp_util.c ${MAINSRCDIR}/rtpp_time.c \
  ${MAINSRCDIR}/rtpp_network.c ${MAINSRCDIR}/rtpp_netaddr.c \
  ${MAINSRCDIR}/rtpp_netaddr.h $(rtpp_netaddr_AUTOSRCS)
extractaudio_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@ @LIBS_SNDFILE@ -lm -lpthread
extractaudio_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR) -D_BSD_SOURCE
if BUILD_CRYPTO
extractaudio_SOURCES+=eaud_crypto.c eaud_crypto.h srtp_util.c srtp_util.h
extractaudio_LDADD+=@LIBS_SRTP@
endif
extractaudio_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG)
extractaudio_LDFLAGS = $(LTO_FLAG)

extractframes_SOURCES = extractframes.c $(EAUD_COMSRCS)
extractframes_LDADD = $(extractaudio_LDADD)
extractframes_CPPFLAGS = $(extractaudio_CPPFLAGS) -DWITHOUT_CRYPTO
extractframes_CFLAGS = $(extractaudio_CFLAGS)
extractframes_LDFLAGS = $(extractaudio_LDFLAGS)

extractaudio_debug_SOURCES = $(extractaudio_SOURCES) $(RTPP_MEMDEB_CORESRCS)
extractaudio_debug_LDADD = $(extractaudio_LDADD) $(RTPP_MEMDEB_LDADD)
extractaudio_debug_CPPFLAGS = $(extractaudio_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=extractaudio
extractaudio_debug_CFLAGS = $(NOPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)
extractaudio_debug_LDFLAGS = $(extractaudio_LDFLAGS)

DEFS=   -DWITHOUT_RTPPLOG $(CC_WFLAGS) @DEFS@
