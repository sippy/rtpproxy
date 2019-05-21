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

SUBDIRS=	libexecinfo libucl makeann $(SUBD_MOD) $(SUBD_ELP) src $(SUBD_UDCNT) tests \
  $(SUBD_EAUD)

dist_man_MANS=	rtpproxy.8
EXTRA_DIST=	README.remote doc rpm/rtpproxy.init rpm/rtpproxy.spec \
 LICENSE README.md

rtpproxy.8: doc/manpage.xml
	xsltproc /usr/local/share/xsl/docbook/manpages/docbook.xsl doc/manpage.xml

update_autosrc:
	${MAKE} -C src ${.TARGET}
