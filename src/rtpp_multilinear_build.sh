gcc12 -I../autosrc -fsave-optimization-record -Rpass-analysis=loop-vectorize \
 -flto -Wall -O3 -g3 -march=ivybridge rtpp_multilinear.c rtpp_mallocs.c rtpp_refcnt.c \
 -o rtpp_multilinear
