bin_PROGRAMS=udp_contention
MAINSRCDIR=$(top_srcdir)/src
udp_contention_SOURCES=udp_contention.c
udp_contention_LDADD=-lm -lpthread
DEFS=   -I$(MAINSRCDIR) @DEFS@

if BUILD_ELPERIODIC
udp_contention_SOURCES+=${MAINSRCDIR}/rtpp_math.c
DEFS+=	-I$(top_srcdir)/libelperiodic/src
endif
udp_contention_LDADD+=@LIBS_ELPERIODIC@
