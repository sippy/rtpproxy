#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.58)
AC_INIT(rtpproxy, 2.2.alpha.20160822, sobomax@sippysoft.com)
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

case "${host_os}" in
freebsd*)
  CPPFLAGS="-I/usr/local/include -pthread"
  LDFLAGS="-L/usr/local/lib"
  #LIBS=
  ;;
linux*)
  CPPFLAGS="-D_BSD_SOURCE -D_ISOC99_SOURCE -DLINUX_XXX"
  LIBS="-lrt"
  ;;
solaris*)
  LIBS="-lsocket -lnsl -lxnet -lrt"
  ;;
*)
  ;;
esac

AC_ARG_ENABLE(systemd,
AS_HELP_STRING([--enable-systemd], [enable systemd support in rtpproxy]),
[],
[enable_systemd=no])

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
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h err.h endian.h sys/endian.h])

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
AC_CHECK_FUNCS([atexit gettimeofday memset mkdir socket strchr strdup strerror])
if test "x$GCC" = "xyes"; then
  ## We like to use C99 routines when available.  This makes sure that
  ## __STDC_VERSION__ is set such that libc includes make them available.
  AM_CFLAGS="-std=gnu99 -Wall -Wno-uninitialized"
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

AM_CONDITIONAL(BUILD_EXTRACTAUDIO, [test "${LIBS_SNDFILE}" != ""])
AM_CONDITIONAL(BUILD_MODULES, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(ENABLE_MODULE_IF, [test "${ENABLE_MODULE_IF}" = 1])
AM_CONDITIONAL(BUILD_ELPERIODIC, [test "${EXTERNAL_ELPERIODIC}" != 1])
AM_CONDITIONAL(BUILD_CRYPTO, [test "${LIBS_SRTP}" != ""])

AC_CONFIG_FILES([Makefile src/Makefile makeann/Makefile tests/Makefile
 extractaudio/Makefile libexecinfo/Makefile modules/Makefile
 modules/acct_csv/Makefile pertools/Makefile pertools/udp_contention/Makefile
 libelperiodic/Makefile])
AC_SUBST(AM_CFLAGS)
AC_SUBST(LIBS_DL)
AC_SUBST(LIBS_GSM)
AC_SUBST(LIBS_G729)
AC_SUBST(LIBS_G722)
AC_SUBST(LIBS_SNDFILE)
AC_SUBST(LIBS_DL)
AC_SUBST(LIBS_SRTP)
AC_OUTPUT
