ACLOCAL_AMFLAGS=	-I m4

AUTOMAKE_OPTIONS=	foreign

if BUILD_MODULES
SUBD_MOD=	modules
endif
if BUILD_ELPERIODIC
SUBD_ELP=       libelperiodic/src
endif
if BUILD_EXTRACTAUDIO
SUBD_EAUD=       extractaudio
endif
if BUILD_UDP_CONTENTION
SUBD_UDCNT=	pertools
endif
if BUILD_DOCS
SUBD_DOCS=	doc
endif

SUBDIRS=	libexecinfo libucl makeann $(SUBD_MOD) $(SUBD_ELP) src $(SUBD_UDCNT) tests \
  $(SUBD_EAUD) ${SUBD_DOCS}

dist_man_MANS=	rtpproxy.8
EXTRA_DIST=	README.remote doc rpm/rtpproxy.init rpm/rtpproxy.spec \
 LICENSE README.md

if BUILD_DOCS
rtpproxy.8: doc/manpage.xml
	${XSLTPROC} ${XSLTPROC_FLAGS} http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl doc/manpage.xml
endif

update_autosrc:
	${MAKE} -C src ${.TARGET}
