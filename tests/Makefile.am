TESTS = # empty
CLEANFILES = # empty
EXTRA_DIST = # empty

include $(srcdir)/autosrc/Makefile.ami
include $(srcdir)/makeann/Makefile.ami
include $(srcdir)/unittests/Makefile.ami
include $(srcdir)/libucl/Makefile.ami
include $(srcdir)/libexecinfo/Makefile.ami
include $(srcdir)/acct_rtcp_hep/Makefile.ami
include $(srcdir)/rtp_analyze/Makefile.ami
include $(srcdir)/extractaudio/Makefile.ami
include $(srcdir)/startstop/Makefile.ami
include $(srcdir)/basic_versions/Makefile.ami
include $(srcdir)/command_parser/Makefile.ami
include $(srcdir)/forwarding/Makefile.ami
include $(srcdir)/memdeb/Makefile.ami
include $(srcdir)/session_timeouts/Makefile.ami
include $(srcdir)/playback/Makefile.ami

EXTRA_DIST += Makefile.am ringback.sln
# NB: AM_TESTS_ENVIRONMENT not available until automake 1.12
TESTS_ENVIRONMENT = \
        BASEDIR=${abs_srcdir} ; export BASEDIR ; \
        BUILDDIR=${abs_builddir} ; export BUILDDIR ; \
        TOP_BUILDDIR=${abs_top_builddir} ; export TOP_BUILDDIR ;
CLEANFILES += *.core

list_tests:
	@echo ${TESTS}
