/*
 * Copyright (c) 2018-2019 Sippy Software, Inc., http://www.sippysoft.com
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
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_time.h"

#if defined(RTPP_DEBUG)
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_stacktrace.h"
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

struct dummy {
    struct {
        struct rtpp_refcnt *rcnt;
    } pub;
};

static struct dummy *
rtpp_rzmalloc_perf(void)
{
    struct dummy *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct dummy), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    return (pvt);

e0:
    return (NULL);
}

static struct dummy *
rtpp_refcnt_perf(void)
{
    struct dummy *pvt;

    pvt = rtpp_zmalloc(sizeof(struct dummy));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rtpp_refcnt_ctor(pvt, NULL);
    if (pvt->pub.rcnt == NULL) {
        goto e1;
    }
    return (pvt);
e1:
    free(pvt);
e0:
    return (NULL);
}

#if defined(RTPP_DEBUG)
static struct dummy *
rtpp_refcnt_trace_perf(void)
{
    struct dummy *pvt;
    static int once = 1;

    pvt = rtpp_zmalloc(sizeof(struct dummy));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rtpp_refcnt_ctor(pvt, NULL);
    if (pvt->pub.rcnt == NULL) {
        goto e1;
    }
    if (once) {
        CALL_SMETHOD(pvt->pub.rcnt, traceen, HEREVAL);
        once = 0;
    }
    return (pvt);
e1:
    free(pvt);
e0:
    return (NULL);
}
#endif

#define TESTOPS (4 * 10000000)

DEFINE_RAW_METHOD(perf_func_ctor, struct dummy *, void);

int
main(int argc, char **argv)
{
    long long i, j, k;
    struct dummy *dpbuf[1000];
    double stime, etime;
    struct {
       perf_func_ctor_t pfunc_ctor;
       const char *tname;
    } *tp, tests[] = {
       {.pfunc_ctor = rtpp_rzmalloc_perf, .tname = "rtpp_rzmalloc()"},
       {.pfunc_ctor = rtpp_refcnt_perf, .tname = "rtpp_zmalloc()+rtpp_refcnt()"},
#if defined(RTPP_DEBUG)
       {.pfunc_ctor = rtpp_refcnt_trace_perf, .tname = "rtpp_zmalloc()+rtpp_refcnt(traceen)"},
#endif
       {.tname = NULL}
    };

#if defined(RTPP_DEBUG)
    void *_trp = getreturnaddr(0);
    assert(_trp != NULL);
    assert(execinfo_set_topframe(_trp) == NULL);
    rtpp_stacktrace(SIGCONT);
    assert(execinfo_set_topframe(NULL) == _trp);
#endif

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_APP_INIT();
#endif

    for (tp = &(tests[0]); tp->tname != NULL; tp++) {
        stime = getdtime();
        for (i = 0; i < TESTOPS; i++) {
            j = i % 1000;
            if (i >= 1000) {
                for (k = 0; k < 11; k++) {
                    RTPP_OBJ_DECREF(&(dpbuf[j]->pub));
                }
            }
            dpbuf[j] = tp->pfunc_ctor();
            for (k = 0; k < 10; k++) {
                RTPP_OBJ_INCREF(&(dpbuf[j]->pub));
            }
        }
        for (i = 0; i < 1000; i++) {
            for (k = 0; k < 11; k++) {
                RTPP_OBJ_DECREF(&(dpbuf[i]->pub));
            }
        }
        etime = getdtime() - stime;
        printf("%s: took %f sec, %f ops/sec\n", tp->tname, etime,
          ((double)TESTOPS ) / etime);
    }

#if defined(RTPP_CHECK_LEAKS)
    int ecode = rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) == 0 ? 0 : 1;
#else
    int ecode = 0;
#endif

    return (ecode);
}
