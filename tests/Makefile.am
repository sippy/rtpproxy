include $(srcdir)/startstop/Makefile.ami
include $(srcdir)/memdeb/Makefile.ami
include $(srcdir)/basic_versions/Makefile.ami
include $(srcdir)/command_parser/Makefile.ami
include $(srcdir)/makeann/Makefile.ami
include $(srcdir)/extractaudio/Makefile.ami
include $(srcdir)/session_timeouts/Makefile.ami
include $(srcdir)/forwarding/Makefile.ami
include $(srcdir)/playback/Makefile.ami

TESTS += rtp_analyze1 rtcp2json1 libucl1 \
  libexecinfo1
rtp_analyze1_EXTRA_DIST = rtp_analyze1 rtp_analyze
rtp_analyze1_CLEANFILES = rtp_analyze_*.wav rtp_analyze_*.tout rtp_analyze_*.tlog
rtcp2json1_EXTRA_DIST = rtcp2json1 rtcp2json
rtcp2json1_CLEANFILES = rtcp1.output
libucl1_EXTRA_DIST = libucl1 libucl
libucl1_CLEANFILES = libucl_test.output
libexecinfo1_EXTRA_DIST = libexecinfo1
EXTRA_DIST += Makefile.am \
    ringback.sln \
    ${rtp_analyze1_EXTRA_DIST} ${rtcp2json1_EXTRA_DIST} \
    ${libucl1_EXTRA_DIST} ${libexecinfo1_EXTRA_DIST}
# NB: AM_TESTS_ENVIRONMENT not available until automake 1.12
TESTS_ENVIRONMENT = \
        BASEDIR=${abs_srcdir} ; export BASEDIR ; \
        BUILDDIR=${abs_builddir} ; export BUILDDIR ; \
        TOP_BUILDDIR=${abs_top_builddir} ; export TOP_BUILDDIR ;
CLEANFILES += ${rtp_analyze1_CLEANFILES} ${rtcp2json1_CLEANFILES} ${libucl1_CLEANFILES} *.core

list_tests:
	@echo ${TESTS}
