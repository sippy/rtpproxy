if ENABLE_LTO
LTO_FLAG = -flto
endif

noinst_LTLIBRARIES = libelperiodic.la
libelperiodic_la_SOURCES = periodic.c prdic_math.c \
  elperiodic.h prdic_math.h prdic_timespecops.h prdic_fd.c prdic_fd.h \
  prdic_pfd.c prdic_pfd.h prdic_main_fd.c prdic_main_fd.h \
  prdic_main_pfd.c prdic_main_pfd.h prdic_main.c prdic_main.h \
  prdic_recfilter.c prdic_recfilter.h prdic_shmtrig.c prdic_shmtrig.h \
  prdic_procchain.h prdic_types.h prdic_sign.c prdic_sign.h \
  prdic_sign_ctx.h prdic_sign_impl.h prdic_band.h src/prdic_inst.h \
  src/prdic_time.h
libelperiodic_la_DEPENDENCIES = Symbol.map
libelperiodic_la_CFLAGS = -g3 -O0 -fPIC ${LTO_FLAG}
libelperiodic_la_LDFLAGS = ${LTO_FLAG} -version-info 1 -Wl,--version-script=$(srcdir)/Symbol.map -lm @RT_LIB@

if ENABLE_noinst
noinst_PROGRAMS = testskew
endif
testskew_SOURCES = testskew.c
testskew_CFLAGS = -Wno-format-zero-length ${LTO_FLAG}
testskew_LDFLAGS = ${LTO_FLAG}
testskew_LDADD = libelperiodic.la -lpthread
