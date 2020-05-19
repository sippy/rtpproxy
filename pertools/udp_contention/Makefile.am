include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami

bin_PROGRAMS=udp_contention
udp_contention_SOURCES=udp_contention.c
udp_contention_LDADD=-lm -lpthread
DEFS=   -I$(MAINSRCDIR) @DEFS@

if BUILD_ELPERIODIC
udp_contention_SOURCES+=${MAINSRCDIR}/rtpp_math.c
DEFS+=	-I$(top_srcdir)/libelperiodic/src
endif
udp_contention_LDADD+=@LIBS_ELPERIODIC@
