TESTS = startstop basic_versions command_parser
EXTRA_DIST = Makefile.am startstop basic_versions basic_versions.input \
    basic_versions.output command_parser command_parser.input command_parser.output
# NB: AM_TESTS_ENVIRONMENT not available until automake 1.12
TESTS_ENVIRONMENT = \
        BASEDIR=${abs_srcdir} ; export BASEDIR ; \
        BUILDDIR=${abs_builddir} ; export BUILDDIR ; \
        TOP_BUILDDIR=${abs_top_builddir} ; export TOP_BUILDDIR ;
