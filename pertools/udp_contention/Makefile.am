bin_PROGRAMS=udp_contention
MAINSRCDIR=$(top_srcdir)/src
udp_contention_SOURCES=udp_contention.c
udp_contention_LDADD=-lm -lpthread
DEFS=   -I$(MAINSRCDIR) @DEFS@

if BUILD_ELPERIODIC
udp_contention_SOURCES+=${MAINSRCDIR}/rtpp_math.c
udp_contention_LDADD+=$(top_srcdir)/libelperiodic/src/libelperiodic.a
DEFS+=	-I$(top_srcdir)/libelperiodic/src
else
udp_contention_LDADD+=@LIBS_ELPERIODIC@
endif
