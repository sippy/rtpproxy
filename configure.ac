AC_INIT([libelperiodic],[m4_esyscmd_s([git rev-parse --abbrev-ref HEAD])],[sobomax@sippysoft.com])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([disable])
AM_PATH_PYTHON([2.7],, [:])

AC_PROG_CC

LT_INIT([disable-shared])

mydef_version=`git describe --always --dirty || date "+%Y%m%d%H%M%S"`
AC_DEFINE_UNQUOTED([VERSION_GIT], ["$mydef_version"])

AC_ARG_ENABLE([noinst],
  AS_HELP_STRING([--enable-noinst],[Enable building noinst binaries (default is yes)]),
  [ENABLE_noinst=$enableval],
  [ENABLE_noinst=yes])

AC_ARG_ENABLE([silent],
  AS_HELP_STRING([--enable-silent],[Less verbose build]),
  [ENABLE_SILENT=$enableval],
  [ENABLE_SILENT=no])

AC_ARG_ENABLE(coverage,
  AS_HELP_STRING([--enable-coverage],[enable test coverage support]),
  [AC_DEFINE([ENABLE_COVERAGE])
  CFLAGS="${CFLAGS} --coverage"; LDFLAGS="${LDFLAGS} --coverage"; break], [])

test_lto() {
  if test "${ENABLE_LTO}" != "yes" -a "${ENABLE_LTO}" != "auto" ; then return; fi

  local CFLAGS="$CFLAGS -flto"
  local LDFLAGS="$LDFLAGS -flto"

  AC_MSG_CHECKING([whether linking with -flto works])
  AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]])],
    [AC_MSG_RESULT([yes])
     local _ENABLE_LTO=yes],
    [AC_MSG_RESULT([no])
     local _ENABLE_LTO=no]
  )
  if test "${_ENABLE_LTO}" = "yes"
  then
    ENABLE_LTO="yes"
    return
  fi
  if test "${ENABLE_LTO}" = "auto"
  then
    ENABLE_LTO="no"
    return
  fi
  AC_MSG_ERROR([LTO is not working])
}

AC_ARG_ENABLE(lto,
  AS_HELP_STRING([--enable-lto],[enable LTO (Link-Time Optimization)]),
  [ENABLE_LTO=${enableval}], [ENABLE_LTO=no])

test_lto

AC_ARG_WITH([python],
   [AS_HELP_STRING([--without-python],[disable building/installing of a python module])],
   [AS_IF([test "x$PYTHON" != "x:" -a "$withval" = "no"], [PYTHON=":"])]
   [])

AC_CHECK_FUNC(clock_gettime, [], [
  AC_CHECK_LIB(rt, clock_gettime, RT_LIB="-lrt",
    AC_MSG_ERROR(Unable to find clock_gettime function; required by ocount))])
AC_SUBST(RT_LIB)

AM_CONDITIONAL(ENABLE_LTO, [test "x${ENABLE_LTO}" = "xyes" ])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])
AM_CONDITIONAL(ENABLE_noinst, [test "x${ENABLE_noinst}" = "xyes" ])

if test "${ENABLE_SILENT}" = "yes"
then
  AM_SILENT_RULES([yes])
fi

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
