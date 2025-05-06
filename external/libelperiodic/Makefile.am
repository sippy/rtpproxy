SUBDIRS = src

include_HEADERS = src/elperiodic.h

EXTRA_DIST = setup.py python
pkgpythondir = $(pythondir)/elperiodic

if HAVE_PYTHON
all-local:
	(cd $(srcdir); $(PYTHON) setup.py build \
	    --build-base `readlink -f $(builddir)`/build \
	    --verbose)

install-exec-local:
	mkdir -p $(pkgpythondir)
	$(PYTHON) $(srcdir)/setup.py install \
	    --prefix $(DESTDIR)$(prefix) \
	    --record $(DESTDIR)$(pkgpythondir)/install_files.txt \
	    --verbose

uninstall-local:
	cat $(DESTDIR)$(pkgpythondir)/install_files.txt | xargs rm -rf
	rm -rf $(DESTDIR)$(pkgpythondir)
endif
