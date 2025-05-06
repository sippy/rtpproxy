/*
 * Copyright (c) 2014-2016 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PRDIC_TIMESPECOPS_H_
#define _PRDIC_TIMESPECOPS_H_

#define SEC(x)      ((x)->tv_sec)
#define NSEC(x)     ((x)->tv_nsec)
#define NSEC_IN_SEC 1000000000L

#define timespec2dtime(s) ((double)SEC(s) + \
  (double)NSEC(s) / (double)NSEC_IN_SEC)
#define dtime2timespec(d, tp)                                      \
    do {                                                           \
        SEC(tp) = trunc(d);                                        \
        NSEC(tp) = round((double)NSEC_IN_SEC * ((d) - SEC(tp)));   \
    } while (0)

#define timespeciszero(t) (SEC(t) == 0 && NSEC(t) == 0)

#ifdef timespecadd
#undef timespecadd
#endif
#define timespecadd(vvp, uvp)           \
    do {                                \
        SEC(vvp) += SEC(uvp);           \
        NSEC(vvp) += NSEC(uvp);         \
        if (NSEC(vvp) >= NSEC_IN_SEC) { \
            SEC(vvp)++;                 \
            NSEC(vvp) -= NSEC_IN_SEC;   \
        }                               \
    } while (0)

#ifdef timespecsub
#undef timespecsub
#endif
#define timespecsub(vvp, uvp)           \
    do {                                \
        SEC(vvp) -= SEC(uvp);           \
        NSEC(vvp) -= NSEC(uvp);         \
        if (NSEC(vvp) < 0) {            \
            SEC(vvp)--;                 \
            NSEC(vvp) += NSEC_IN_SEC;   \
        }                               \
    } while (0)

#define timespecsub2(r, v, u)                                         \
    do {                                                              \
        SEC(r) = SEC(v) - SEC(u);                                     \
        NSEC(r) = NSEC(v) - NSEC(u);                                  \
        if (NSEC(r) < 0 && (SEC(r) > 0 || NSEC(r) <= -NSEC_IN_SEC)) { \
            SEC(r)--;                                                 \
            NSEC(r) += NSEC_IN_SEC;                                   \
        }                                                             \
    } while (0);

#define timespecmul(rvp, vvp, uvp)                                 \
    do {                                                           \
        long long tnsec;                                           \
        SEC(rvp) = SEC(vvp) * SEC(uvp);                            \
        tnsec = (long long)(NSEC(vvp) * NSEC(uvp)) / NSEC_IN_SEC;  \
        tnsec += (long long)(SEC(vvp) * NSEC(uvp));                \
        tnsec += (long long)(SEC(uvp) * NSEC(vvp));                \
        if (tnsec >= NSEC_IN_SEC) {                                \
            SEC(rvp) += (tnsec / NSEC_IN_SEC);                     \
            NSEC(rvp) = (tnsec % NSEC_IN_SEC);                     \
        } else {                                                   \
            NSEC(rvp) = tnsec;                                     \
        }                                                          \
    } while (0)
#endif /* _PRDIC_TIMESPECOPS_H_ */
