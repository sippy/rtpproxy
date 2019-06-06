TARGETS = user_manual.html release_info.html

all: $(TARGETS)

XSL = http://docbook.sourceforge.net/release/xsl/current/xhtml/docbook.xsl

user_manual.html: user_manual.xml manpage.xml
	${XSLTPROC} --xinclude -o user_manual.html ${XSLTPROC_FLAGS} $(XSL) user_manual.xml

release_info.html: release_info.xml
	${XSLTPROC} --xinclude -o release_info.html ${XSLTPROC_FLAGS} $(XSL) release_info.xml

clean:
	@rm -f $(TARGETS)
