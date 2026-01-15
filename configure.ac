#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([rtpproxy],[3.1],[sobomax@sippysoft.com])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([serial-tests subdir-objects])
# If the test gets too verbose, comment one line above and uncomment one below
#AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# cross-compile macros
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_MKDIR_P
LT_INIT

mydef_version=`git describe --always --dirty || date "+%Y%m%d%H%M%S"`
AC_DEFINE_UNQUOTED([VERSION_GIT], ["${mydef_version}"], [Git hash])

case "${host_os}" in
freebsd*)
  CPPFLAGS="${CPPFLAGS} -I/usr/local/include -pthread"
  LDFLAGS="${LDFLAGS} -L/usr/local/lib"
  #LIBS=
  ;;
linux*)
  CPPFLAGS="${CPPFLAGS} -D_DEFAULT_SOURCE -D_ISOC99_SOURCE -DLINUX_XXX"
  LIBS="-lrt"
  ;;
solaris*)
  LIBS="-lsocket -lnsl -lxnet -lrt"
  ;;
*)
  ;;
esac
OPT_CFLAGS="`echo "${CFLAGS}" | tr ' ' '\n' | sed 's|^-g$|-g3|' | tr '\n' ' '` -fvisibility=hidden"
CFLAGS="`echo ${CFLAGS} | tr ' ' '\n' | grep -v '^-O.*' | uniq | tr '\n' ' '` -fvisibility=hidden"

AX_COMPILE_CHECK_SIZEOF(time_t, [#include <time.h>])
AX_CHECK_COMPILE_FLAG([-Wno-frame-address], [CFLAGS="${CFLAGS} -Wno-frame-address"], [], [-Werror])

AC_MSG_CHECKING([whether '$CC' supports -Wincompatible-pointer-types])
ac_save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -Wincompatible-pointer-types"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([struct foo; struct bar;],
  [[struct foo *f; struct bar *b; f = b;]])],
  [ac_cc_warn_ipt=1], [ac_cc_warn_ipt=0])
AS_IF([test $ac_cc_warn_ipt -ne 0],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])
CFLAGS="$ac_save_CFLAGS"

mused="[[[maybe_unused]]]"
AC_MSG_CHECKING([whether '$CC' supports '${mused}' ])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([${mused} int bar=42;],
  [])],
  [
   AC_MSG_RESULT([yes])
   AC_DEFINE_UNQUOTED([MAYBE_UNUSED], [${mused}], [Define if you have the [[maybe_unused]].])
  ], [
   AC_MSG_RESULT([no])
   AC_DEFINE_UNQUOTED([MAYBE_UNUSED], [], [Define if you have the [[maybe_unused]].])
  ])

AC_ARG_ENABLE(systemd,
AS_HELP_STRING([--enable-systemd], [enable systemd support in rtpproxy]),
[],
[enable_systemd=no])

AC_ARG_ENABLE(coverage,
  AS_HELP_STRING([--enable-coverage],[enable test coverage support]),
  [ENABLE_COVERAGE=${enableval}], [ENABLE_COVERAGE=no])

AC_ARG_ENABLE(memglitching,
  AS_HELP_STRING([--enable-memglitching],[enable advanced tests around malloc glitching]),
  [ENABLE_MEMGLITCHING=${enableval}], [ENABLE_MEMGLITCHING=no])

AC_ARG_ENABLE(basic-tests,
  AS_HELP_STRING([--enable-basic-tests],[enable basic functionality tests]),
  [ENABLE_BASIC_TESTS=${enableval}], [ENABLE_BASIC_TESTS=yes])

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
  AS_HELP_STRING([--enable-lto],[enable LTO (Link-Time Optimization): yes/no/auto]),
  [ENABLE_LTO=${enableval}], [ENABLE_LTO=no])

test_lto

AC_ARG_ENABLE(librtpproxy,
  AS_HELP_STRING([--enable-librtpproxy],[Build librtpproxy for instrumentation]),
  [ENABLE_LIBRTPPROXY=${enableval}], [ENABLE_LIBRTPPROXY=no])

if test "$ENABLE_COVERAGE" = 'yes'
then
  AC_DEFINE([ENABLE_COVERAGE], [1], [Test coverage support is enabled])
  CFLAGS="${CFLAGS} --coverage"
  LDFLAGS="${LDFLAGS} --coverage"
fi

AC_ARG_ENABLE([noinst],
  AS_HELP_STRING([--enable-noinst],[Enable building noinst binaries (default is yes)]),
  [ENABLE_noinst=$enableval],
  [ENABLE_noinst=yes])

AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug],[Enable building debug binaries (default is yes)]),
  [ENABLE_debug=$enableval],
  [ENABLE_debug=yes])

AC_ARG_ENABLE([silent],
  AS_HELP_STRING([--enable-silent],[Less verbose build]),
  [ENABLE_SILENT=$enableval],
  [ENABLE_SILENT=no])

AC_ARG_ENABLE([static-crypto],
  AS_HELP_STRING([--enable-static-crypto], [Link statically against libssl, libcrypto, libsrtp2]),
  [ENABLE_STATIC_CRYPTO=$enableval],
  [ENABLE_STATIC_CRYPTO=no])

if test "$ENABLE_STATIC_CRYPTO" = yes; then
  LIB_CRYPTO="${LIB_CRYPTO_STATIC:-"-l:libcrypto.a -lpthread"}"
  LIB_SSL='-l:libssl.a'
  LIB_SRTP2='-l:libsrtp2.a'
else
  LIB_CRYPTO='-lcrypto'
  LIB_SSL='-lssl'
  LIB_SRTP2='-lsrtp2'
fi

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
  if test "${enable_shared}" = yes
  then
    ENABLE_MODULE_IF=1
    AC_DEFINE([ENABLE_MODULE_IF], [1], [Define to enable dymanic modules])
  fi
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
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <bcg729/encoder.h>]], [[initBcg729EncoderChannel();]])],[new_bcg729_api=no],[new_bcg729_api=yes])
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

# libsrtp2 (preferred)
AC_CHECK_HEADER(srtp2/srtp.h, found_libsrtp2=yes)
if test "$found_libsrtp2" = yes
then
  save_LIBS="${LIBS}"
  LIBS="${LIBS} ${LIB_CRYPTO}"
  AC_CHECK_LIB([srtp2], [srtp_protect_mki], [_sp_nargs=3], [_sp_nargs=4])
  AC_MSG_CHECKING([for srtp_init in -lsrtp2])
  LIBS="${save_LIBS} ${LIB_SRTP2} ${LIB_CRYPTO}"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
      #include <srtp2/srtp.h>
    ], [
      return (int)srtp_init();
    ])], [
   AC_MSG_RESULT([yes])
   LIBS_SRTP="${LIB_SRTP2} ${LIB_CRYPTO}"
   # Test program to check if the srtp_protect function accepts size_t* argument
   AC_MSG_CHECKING(['srtp_protect()' last argument type])
   original_cflags="$CFLAGS"
   CFLAGS="${CFLAGS} -Werror -DSRTP_PROTECT_NARGS=${_sp_nargs}"
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
     #include <stdlib.h>
     #include <srtp2/srtp.h>],
     [srtp_t ctx; void* rtp_hdr; size_t len;
     #if SRTP_PROTECT_NARGS == 4
     return srtp_protect(ctx, rtp_hdr, &len, 0);
     #else
     return srtp_protect(ctx, rtp_hdr, &len);
     #endif])],
     [srtp_protect_lastarg=size_t], [srtp_protect_lastarg=int])
   CFLAGS="$original_cflags"
   AC_MSG_RESULT([$srtp_protect_lastarg])
   AC_DEFINE_UNQUOTED([SRTP_PROTECT_LASTARG], [${srtp_protect_lastarg}], [Type of the last argument of the srtp_protect() API])
   AC_DEFINE_UNQUOTED([SRTP_PROTECT_NARGS], [${_sp_nargs}], [Number of srtp_protect() arguments])
   AC_DEFINE([ENABLE_SRTP2], 1, [Define if you have libsrtp2 library installed])
  ], [
   AC_MSG_RESULT([no])
  ])
  LIBS="${save_LIBS}"
else
  # libsrtp
  AC_CHECK_HEADER(srtp/srtp.h, found_libsrtp=yes)
  if test "$found_libsrtp" = yes
  then
    AC_CHECK_LIB(srtp, srtp_init,
     LIBS_SRTP="${LIB_SRTP2} ${LIB_CRYPTO}"
     AC_DEFINE([ENABLE_SRTP], 1, [Define if you have libsrtp library installed]))
  fi
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
  SUBD_ELP="external/libelperiodic/src"
fi

if test "${EXTERNAL_ELPERIODIC}" != 1
then
  LIBS_ELPERIODIC="\$(top_srcdir)/external/libelperiodic/src/libelperiodic.la"
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

AC_CHECK_HEADER(libunwind.h, found_libunwind=yes)
if test "$found_libunwind" = yes
then
  AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([[
      #include <stddef.h>
      #define UNW_LOCAL_ONLY
      #include <libunwind.h>
    ]],
    [[
      unw_getcontext(NULL);
    ]])],
    [
      AC_CHECK_LIB(unwind, unw_backtrace,
       LIBS_UNWIND="-lunwind"
       ENABLE_LIBUNWIND=1
       AC_DEFINE([ENABLE_LIBUNWIND], 1, [Define if you have libunwind library installed])
      )
    ]
  )
fi

AC_CHECK_HEADER(stdatomic.h, found_stdatomic=yes)
if test "$found_stdatomic" = yes
then
  ENABLE_OBJCK=1
  AC_DEFINE([ENABLE_OBJCK], 1, [Define if you want to build rtpp_objck test app])
fi

AC_CHECK_HEADER(sys/epoll.h, found_epoll=yes)
if test "$found_epoll" != yes
then
  AC_CHECK_HEADER(sys/event.h, found_kevent=yes,
   AC_MSG_ERROR([Neither epoll not kqueue is found]))
  AC_DEFINE([HAVE_KQUEUE], 1, [Have kqueue(2) interface.])
else
  AC_DEFINE([HAVE_EPOLL], 1, [Have epoll(2) interface.])
fi

## Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h])
AC_CHECK_HEADERS([string.h strings.h sys/socket.h sys/time.h unistd.h err.h endian.h sys/endian.h])
AC_CHECK_HEADERS([libgen.h stdio.h float.h math.h sys/mman.h ctype.h errno.h sys/sysctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST


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

AC_MSG_CHECKING([whether -latomic is needed for __atomic builtins])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[#include <stdint.h>]],
    [[uint64_t val = 0; __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);]]
  )],
  [AC_MSG_RESULT([no])],
  [LIBS="$LIBS -latomic"
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([[#include <stdint.h>]],
                       [[uint64_t val = 0; __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);]]
      )],
      [AC_MSG_RESULT([yes])],
      [AC_MSG_FAILURE([libatomic needed, but linking with -latomic failed, cannot continue])]
  )]
)
AC_CHECK_FUNCS([pthread_yield pthread_setname_np])

AC_ARG_ENABLE(docs,
  AS_HELP_STRING([--enable-docs],[enable generation of documentation]),
  [ENABLE_DOCS=${enableval}], [ENABLE_DOCS=no])

if test "${ENABLE_DOCS}" = "yes"
then
  # <DocBook & friends>
  AX_CHECK_DOCBOOK_DTD(4.5)
  if test "x$HAVE_DOCBOOK_DTD_4_5" = "xyes"
  then
    AC_CHECK_PROG(HAVE_FOP, fop, yes)
  fi
  # </DocBook & friends>
fi

AC_MSG_CHECKING([for SO_TS_CLOCK/SO_TS_MONOTONIC])
AC_COMPILE_IFELSE( [AC_LANG_PROGRAM([[
  #include <sys/types.h>
  #include <sys/socket.h>
  ]],
  [[
  int stype = SO_TS_MONOTONIC;
  struct cmsghdr mymsg = {.cmsg_type = SCM_MONOTONIC};
  setsockopt(0, 0, SO_TS_CLOCK, &stype, sizeof(stype));
  ]])],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE_UNQUOTED([HAVE_SO_TS_CLOCK], 1, [Define to 1 if you have the SO_TS_CLOCK.])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE_UNQUOTED([HAVE_SO_TS_CLOCK], 0, [Define to 1 if you have the SO_TS_CLOCK.])
]
)

AM_CONDITIONAL(BUILD_EXTRACTAUDIO, [test "${LIBS_SNDFILE}" != ""])
AM_CONDITIONAL(BUILD_MODULES, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(ENABLE_MODULE_IF, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(BUILD_ELPERIODIC, [test "${EXTERNAL_ELPERIODIC}" != 1])
AM_CONDITIONAL(BUILD_CRYPTO, [test "${LIBS_SRTP}" != ""])
AM_CONDITIONAL(BUILD_LOG_STAND, [test "${LIBS_SIPLOG}" = ""])
AM_CONDITIONAL(BUILD_UDP_CONTENTION, [test "${ENABLE_UDP_CONTENTION}" = 1])
AM_CONDITIONAL(BUILD_OBJCK, [test "${ENABLE_OBJCK}" = 1])
AM_CONDITIONAL(BUILD_DOCS, [test "x${HAVE_DOCBOOK_DTD_4_5}" = "xyes" ])
AM_CONDITIONAL(ENABLE_MEMGLITCHING, [test "x${ENABLE_MEMGLITCHING}" = "xyes" ])
AM_CONDITIONAL(ENABLE_BASIC_TESTS, [test "x${ENABLE_BASIC_TESTS}" = "xyes" ])
AM_CONDITIONAL(ENABLE_WARN_IPT, [test "${ac_cc_warn_ipt}" = 1])
AM_CONDITIONAL(ENABLE_LTO, [test "x${ENABLE_LTO}" = "xyes" ])
AM_CONDITIONAL(ENABLE_LIBRTPPROXY, [test "x${ENABLE_LIBRTPPROXY}" = "xyes" ])
AM_CONDITIONAL(ENABLE_LIBUNWIND, [test "${ENABLE_LIBUNWIND}" = 1 ])
AM_CONDITIONAL(ENABLE_noinst, [test "x${ENABLE_noinst}" = "xyes" ])
AM_CONDITIONAL(ENABLE_debug, [test "x${ENABLE_debug}" = "xyes" ])
AM_CONDITIONAL([TESTS_EXIST], [test -d "$srcdir/tests"])

if test "${ENABLE_SILENT}" = "yes"
then
  AM_SILENT_RULES([yes])
fi

AC_CONFIG_FILES([Makefile src/Makefile makeann/Makefile
 extractaudio/Makefile libexecinfo/Makefile modules/Makefile
 modules/acct_csv/Makefile modules/acct_rtcp_hep/Makefile
 modules/catch_dtmf/Makefile modules/badmod/Makefile libxxHash/Makefile
 libre/Makefile modules/dtls_gw/Makefile modules/ice_lite/Makefile
 pertools/Makefile pertools/udp_contention/Makefile libucl/Makefile
 doc/Makefile])

AM_COND_IF([TESTS_EXIST], [
  AC_CONFIG_FILES([tests/Makefile])
])

AM_COND_IF([BUILD_ELPERIODIC], [
  ac_configure_args="$ac_configure_args \"CFLAGS=$CFLAGS\""
  AC_CONFIG_SUBDIRS([external/libelperiodic])
])

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
AC_SUBST(LIBS_UNWIND)
AC_SUBST(SIZEOF_TIME_T)
AC_SUBST(OPT_CFLAGS)
AC_SUBST(LIB_CRYPTO)
AC_SUBST(LIB_SSL)
AC_SUBST(LIB_SRTP2)
AC_OUTPUT
