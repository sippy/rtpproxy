TESTS = # empty
CLEANFILES = # empty
EXTRA_DIST = # empty

if ENABLE_BASIC_TESTS
include $(srcdir)/autosrc/Makefile.ami
include $(srcdir)/recording/Makefile.ami
#temp#include $(srcdir)/makeann/Makefile.ami
#temp#include $(srcdir)/unittests/Makefile.ami
#temp#include $(srcdir)/libucl/Makefile.ami
#temp#include $(srcdir)/libexecinfo/Makefile.ami
#temp#include $(srcdir)/acct_rtcp_hep/Makefile.ami
#temp#include $(srcdir)/rtp_analyze/Makefile.ami
#temp#include $(srcdir)/extractaudio/Makefile.ami
#temp#include $(srcdir)/startstop/Makefile.ami
#temp#include $(srcdir)/basic_versions/Makefile.ami
#temp#include $(srcdir)/command_parser/Makefile.ami
#temp#include $(srcdir)/forwarding/Makefile.ami
#temp#include $(srcdir)/session_timeouts/Makefile.ami
#temp#include $(srcdir)/playback/Makefile.ami
endif
if ENABLE_MEMGLITCHING
#temp#include $(srcdir)/makeann/Makefile.ami
#temp#include $(srcdir)/memdeb/Makefile.ami
endif

EXTRA_DIST += Makefile.am ringback.sln
# NB: AM_TESTS_ENVIRONMENT not available until automake 1.12
TESTS_ENVIRONMENT = \
        BASEDIR=${abs_srcdir} ; export BASEDIR ; \
        BUILDDIR=${abs_builddir} ; export BUILDDIR ; \
        TOP_BUILDDIR=${abs_top_builddir} ; export TOP_BUILDDIR ;
CLEANFILES += *.core

list_tests:
	@echo ${TESTS}
