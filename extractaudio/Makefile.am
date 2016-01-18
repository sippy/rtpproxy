bin_PROGRAMS=extractaudio
MAINSRCDIR=$(top_srcdir)/src
extractaudio_SOURCES=main.c decoder.c rtpp_loader.c ${MAINSRCDIR}/rtp.c \
  ${MAINSRCDIR}/rtp_analyze.c ${MAINSRCDIR}/rtpp_util.c ${MAINSRCDIR}/rtpp_time.c \
  ${MAINSRCDIR}/rtpp_log_stand.c decoder.h format_au.h g711.h rtpp_loader.h \
  session.h g729_compat.c g729_compat.h ${MAINSRCDIR}/rtpp_network.c \
  ${MAINSRCDIR}/rtpp_monotime.c ${MAINSRCDIR}/rtpp_mallocs.c \
  ${MAINSRCDIR}/rtpp_refcnt.c ${MAINSRCDIR}/rtpp_refcnt_fin.c \
  ${MAINSRCDIR}/rtpp_refcnt_fin.h ${MAINSRCDIR}/rtpp_ringbuf.c \
  ${MAINSRCDIR}/rtpp_ringbuf_fin.c ${MAINSRCDIR}/rtpp_ringbuf_fin.h
extractaudio_LDADD=@LIBS_G729@ @LIBS_GSM@ @LIBS_G722@ @LIBS_SNDFILE@ -lm -lpthread

DEFS=   -DWITHOUT_SIPLOG -Wall -D"rtpp_log_t=void *" \
  -D"rtpp_log_write(lvl, ld, format, args...)=fprintf(stderr, format, \#\# args)" \
  @DEFS@

${MAINSRCDIR}/rtpp_refcnt_fin.c:
	$(MAKE) -C ${MAINSRCDIR} rtpp_refcnt_fin.c

${MAINSRCDIR}/rtpp_refcnt_fin.h:
	$(MAKE) -C ${MAINSRCDIR} rtpp_refcnt_fin.h

${MAINSRCDIR}/rtpp_ringbuf_fin.c:
	$(MAKE) -C ${MAINSRCDIR} rtpp_ringbuf_fin.c

${MAINSRCDIR}/rtpp_ringbuf_fin.h:
	$(MAKE) -C ${MAINSRCDIR} rtpp_ringbuf_fin.h
