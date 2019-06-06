#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.58)
AC_INIT(rtpproxy, 2.2.alpha, sobomax@sippysoft.com)
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_MKDIR_P
AM_PROG_CC_C_O
LT_INIT

mydef_version=`git describe --always --dirty || date "+%Y%m%d%H%M%S"`
AC_DEFINE([VERSION_GIT], [], [Git hash])
AC_DEFINE_UNQUOTED([VERSION_GIT],["$mydef_version"])

case "${host_os}" in
freebsd*)
  CPPFLAGS="-I/usr/local/include -pthread"
  LDFLAGS="-L/usr/local/lib"
  #LIBS=
  ;;
linux*)
  CPPFLAGS="-D_DEFAULT_SOURCE -D_ISOC99_SOURCE -DLINUX_XXX"
  LIBS="-lrt"
  ;;
solaris*)
  LIBS="-lsocket -lnsl -lxnet -lrt"
  ;;
*)
  ;;
esac

AX_COMPILE_CHECK_SIZEOF(time_t, [#include <time.h>])

AC_ARG_ENABLE(systemd,
AS_HELP_STRING([--enable-systemd], [enable systemd support in rtpproxy]),
[],
[enable_systemd=no])

AC_ARG_ENABLE(coverage,
  AC_HELP_STRING([--enable-coverage], [enable test coverage support]),
  AC_DEFINE([ENABLE_COVERAGE], [], [Test coverage support is enabled])
  CFLAGS="${CFLAGS} --coverage"; LDFLAGS="${LDFLAGS} --coverage"; break], [])

# Checks for libraries.

if test "$enable_systemd" = 'yes'
then
  AC_SEARCH_LIBS(sd_listen_fds,[systemd systemd-daemon],
   [have_sd_listen_fds=yes],
   [AC_MSG_ERROR([Cannot find sd_listen_fds function])],)
  AC_CHECK_HEADER(systemd/sd-daemon.h,
   [have_systemd_sd_daemon_h=yes],
   [AC_MSG_ERROR([Cannot find <systemd/sd-daemon.h> header])])
  if test x"$have_sd_listen_fds" = x"yes" && \
     test x"$have_systemd_sd_daemon_h" = x"yes"
  then
     AC_DEFINE([HAVE_SYSTEMD_DAEMON],[1],[Define if you have systemd daemon])
  fi

fi

# dlopen et al
AC_CHECK_HEADER(dlfcn.h, found_dlfcn=yes)
if test "$found_dlfcn" = yes
then
  ENABLE_MODULE_IF=1
  AC_DEFINE([ENABLE_MODULE_IF], 1, [Define to enable dymanic modules])
  AC_CHECK_LIB([dl], [dladdr], [LIBS_DL=-ldl], [LIBS_DL=])
fi

# GSM
AC_CHECK_HEADER(gsm.h, found_libgsm=yes)
if test "$found_libgsm" = yes
then
  AC_CHECK_LIB(gsm, gsm_create,
   LIBS_GSM="-lgsm"
   AC_DEFINE([ENABLE_GSM], 1, [Define if you have libgsm library installed]))
fi

# G.729
AC_CHECK_HEADER(g729_encoder.h, found_libg729=yes)
if test "$found_libg729" = yes
then
  AC_CHECK_LIB(g729, g729_encoder_new,
   LIBS_G729="-lg729 -lm"
   AC_DEFINE([ENABLE_G729], 1, [Define if you have G.729 support]),,
   -lm
  )
else
  AC_CHECK_HEADER(bcg729/encoder.h, found_libbcg729=yes)
  if test "$found_libbcg729" = yes
  then
    AC_CHECK_LIB(bcg729, initBcg729EncoderChannel,
     LIBS_G729=`pkg-config --libs libbcg729`
     AC_DEFINE([ENABLE_G729], 1, [Define if you have G.729 support])
     AC_DEFINE([ENABLE_BCG729], 1, [Define if you have bcg729 library])
    )
  fi
fi
if test "$found_libbcg729" = yes
then
  AC_TRY_COMPILE([#include <bcg729/encoder.h>],
   [initBcg729EncoderChannel();],
   new_bcg729_api=no,
   new_bcg729_api=yes)
  if test "$new_bcg729_api" = yes
  then
    AC_DEFINE(HAVE_NEW_BCG729_API, 1,
     [define to 1 if bcg729 new API have to be used])
  fi
fi

# G.722
AC_CHECK_HEADER(g722.h, found_libg722=yes)
if test "$found_libg722" = yes
then
  AC_CHECK_LIB(g722, g722_encoder_new,
   LIBS_G722="-lg722"
   AC_DEFINE([ENABLE_G722], 1, [Define if you have libg722 library installed]))
fi

# libsndfile
AC_CHECK_HEADER(sndfile.h, found_libsndfile=yes)
if test "$found_libsndfile" = yes
then
  AC_CHECK_LIB(sndfile, sf_open,
   LIBS_SNDFILE="-lsndfile"
   AC_DEFINE([ENABLE_SNDFILE], 1, [Define if you have libsndfile library installed]))
fi

# libsrtp
AC_CHECK_HEADER(srtp/srtp.h, found_libsrtp=yes)
if test "$found_libsrtp" = yes
then
  AC_CHECK_LIB(srtp, srtp_init,
   LIBS_SRTP="-lsrtp"
   AC_DEFINE([ENABLE_SRTP], 1, [Define if you have libsrtp library installed]))
fi

# libsrtp2
AC_CHECK_HEADER(srtp2/srtp.h, found_libsrtp2=yes)
if test "$found_libsrtp2" = yes
then
  AC_CHECK_LIB(srtp2, srtp_init,
   LIBS_SRTP="-lsrtp2"
   AC_DEFINE([ENABLE_SRTP2], 1, [Define if you have libsrtp2 library installed]))
fi

# libelperiodic
AC_CHECK_HEADER(elperiodic.h, found_libelperiodic=yes)
if test "$found_libelperiodic" = yes
then
  AC_CHECK_LIB(elperiodic, prdic_init,
   LIBS_ELPERIODIC="-lelperiodic -lm"
   EXTERNAL_ELPERIODIC=1
   ,,-lm)
else
  SUBD_ELP="libelperiodic/src"
fi

if test "${EXTERNAL_ELPERIODIC}" != 1
then
  LIBS_ELPERIODIC="\$(top_srcdir)/libelperiodic/src/libelperiodic.la"
fi

# libsiplog
AC_CHECK_HEADER(siplog.h, found_libsiplog=yes)
if test "$found_libsiplog" = yes
then
  AC_CHECK_LIB(siplog, siplog_open,
   LIBS_SIPLOG="-lsiplog"
   LIBS_SIPLOG_DBG="-lsiplog_debug"
   AC_DEFINE([ENABLE_SIPLOG], 1, [Define if you have libsiplog library installed]))
fi

AC_CHECK_HEADER(stdatomic.h, found_stdatomic=yes)
if test "$found_stdatomic" = yes
then
  ENABLE_OBJCK=1
  AC_DEFINE([ENABLE_OBJCK], 1, [Define if you want to build rtpp_objck test app])
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h])
AC_CHECK_HEADERS([string.h strings.h sys/socket.h sys/time.h unistd.h err.h endian.h sys/endian.h])
AC_CHECK_HEADERS([libgen.h stdio.h float.h math.h sys/mman.h ctype.h errno.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

dnl check for the sockaddr_un.sun_len member
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
  [AC_DEFINE(HAVE_SOCKADDR_SUN_LEN,1,[Have the sockaddr_un.sun_len member.])],
  [],
  [ #include <sys/types.h>
  #include <sys/un.h>
  ])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([atexit gettimeofday memset mkdir socket strchr strdup strerror strlcpy])
if test "x$GCC" = "xyes"; then
  ## We like to use C99 routines when available.  This makes sure that
  ## __STDC_VERSION__ is set such that libc includes make them available.
  AM_CFLAGS="-std=gnu99 -Wall -Wno-uninitialized"
fi

AC_CHECK_FUNC(clock_gettime, [], [
  AC_CHECK_LIB(rt, clock_gettime, RT_LIB="-lrt",
    AC_MSG_ERROR(Unable to find clock_gettime function; required by ocount))])
AC_SUBST(RT_LIB)

AC_MSG_CHECKING([for rdtsc])
AC_LINK_IFELSE([AC_LANG_PROGRAM(
  [[
   #include <sys/types.h>
   #include <stdint.h>
   #if defined(__FreeBSD__)
   # include <sys/cdefs.h>
   # include <machine/cpufunc.h>
   #else
   static uint64_t
   rdtsc(void)
   {
     uint32_t low, high;

      __asm __volatile("rdtsc" : "=a" (low), "=d" (high));
      return (low | ((uint64_t)high << 32));
   }
   #endif
  ]],
  [[
   rdtsc();
  ]])],
  [
   AC_MSG_RESULT([yes])
   found_rdtsc=yes
  ],
  [
   AC_MSG_RESULT([no])
  ]
)

if test "$found_rdtsc" = yes
then
  ENABLE_UDP_CONTENTION=1
  AC_DEFINE([ENABLE_UDP_CONTENTION], 1, [Define to build udp_contention utility])
fi

AC_MSG_CHECKING([for __sync_fetch_and_add])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE([
    int main(void) {
        volatile int rcval = 1, rcval_pre;
        rcval_pre = __sync_fetch_and_add(&rcval, -1);
        return(rcval == 0 && rcval_pre == 1 ? 0 : 1);
    }
   ])],
     [AC_MSG_RESULT([yes])
     AC_DEFINE([HAVE_GCC_ATOMICS],[1],[Define if you have gcc-style atomic operations])],
   [AC_MSG_RESULT([no])]
)


# <DocBook & friends>
AX_CHECK_DOCBOOK_DTD(4.5)
if test "x$HAVE_DOCBOOK_DTD_4_5" = "xyes"
then
  AC_CHECK_PROG(HAVE_FOP, fop, yes)
fi
# </DocBook & friends>

AM_CONDITIONAL(BUILD_EXTRACTAUDIO, [test "${LIBS_SNDFILE}" != ""])
AM_CONDITIONAL(BUILD_MODULES, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(ENABLE_MODULE_IF, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(BUILD_ELPERIODIC, [test "${EXTERNAL_ELPERIODIC}" != 1])
AM_CONDITIONAL(BUILD_CRYPTO, [test "${LIBS_SRTP}" != ""])
AM_CONDITIONAL(BUILD_LOG_STAND, [test "${LIBS_SIPLOG}" = ""])
AM_CONDITIONAL(BUILD_UDP_CONTENTION, [test "${ENABLE_UDP_CONTENTION}" = 1])
AM_CONDITIONAL(BUILD_OBJCK, [test "${ENABLE_OBJCK}" = 1])
AM_CONDITIONAL(BUILD_DOCS, [test "x${HAVE_DOCBOOK_DTD_4_5}" = "xyes" ])

AC_CONFIG_FILES([Makefile src/Makefile makeann/Makefile tests/Makefile
 extractaudio/Makefile libexecinfo/Makefile modules/Makefile
 modules/acct_csv/Makefile modules/acct_rtcp_hep/Makefile
 pertools/Makefile pertools/udp_contention/Makefile libucl/Makefile
 python/sippy_lite/sippy/Time/clock_dtime.py doc/Makefile])

AM_COND_IF([BUILD_ELPERIODIC], [AC_CONFIG_SUBDIRS([libelperiodic])])

AC_SUBST(AM_CFLAGS)
AC_SUBST(LIBS_DL)
AC_SUBST(LIBS_GSM)
AC_SUBST(LIBS_G729)
AC_SUBST(LIBS_G722)
AC_SUBST(LIBS_SNDFILE)
AC_SUBST(LIBS_SRTP)
AC_SUBST(LIBS_SIPLOG)
AC_SUBST(LIBS_SIPLOG_DBG)
AC_SUBST(LIBS_ELPERIODIC)
AC_SUBST(SIZEOF_TIME_T)
AC_OUTPUT
