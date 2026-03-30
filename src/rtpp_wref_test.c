/*
 * Copyright (c) 2026 Sippy Software, Inc., http://www.sippysoft.com
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

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_wref.h"

#if defined(_RTPP_MEMDEB_H)
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#endif
#include "rtpp_memdeb_internal.h"

#if defined(_RTPP_MEMDEB_H)
RTPP_MEMDEB_APP_STATIC;
#endif

#define TEST_NREFS 4096

struct test_slot {
    struct rtpp_refcnt *rco;
    struct rtpp_refcnt *orig_rco;
    struct rtpp_wref *wref;
    void *orig_obj;
    uint32_t spinval;
    uint32_t spin_budget;
};

struct test_ctx {
    struct test_slot slots[TEST_NREFS];
    atomic_bool start;
    atomic_bool getter_ready;
    atomic_bool release_done;
    atomic_uint_fast64_t getref_ok;
    atomic_uint_fast64_t getref_null;
};

static void
delay_dtor(void *arg)
{
    struct test_slot *tsp;
    uint32_t v;
    uint32_t i;

    tsp = (struct test_slot *)arg;
    v = tsp->spinval;
    for (i = 0; i < tsp->spin_budget; i++) {
        v = v * 1664525u + 1013904223u;
        atomic_signal_fence(memory_order_seq_cst);
    }
    tsp->spinval = v;
}

static void *
release_run(void *arg)
{
    struct test_ctx *tcp;
    int i;

    tcp = (struct test_ctx *)arg;
    while (!atomic_load_explicit(&tcp->start, memory_order_acquire)) {
        sched_yield();
    }
    while (!atomic_load_explicit(&tcp->getter_ready, memory_order_acquire)) {
        sched_yield();
    }
    for (i = 0; i < TEST_NREFS; i++) {
        RC_DECREF(tcp->slots[i].rco);
        tcp->slots[i].rco = NULL;
        if ((i % 32) == 0) {
            sched_yield();
        }
    }
    atomic_store_explicit(&tcp->release_done, true, memory_order_release);
    return (NULL);
}

static void *
getter_run(void *arg)
{
    struct test_ctx *tcp;
    const struct rtpp_wref_target *href;
    int i;

    tcp = (struct test_ctx *)arg;
    while (!atomic_load_explicit(&tcp->start, memory_order_acquire)) {
        sched_yield();
    }
    atomic_store_explicit(&tcp->getter_ready, true, memory_order_release);
    do {
        for (i = 0; i < TEST_NREFS; i++) {
            href = CALL_SMETHOD(tcp->slots[i].wref, getref);
            if (href == NULL) {
                atomic_fetch_add_explicit(&tcp->getref_null, 1,
                  memory_order_relaxed);
                continue;
            }
            assert(href->rco == tcp->slots[i].orig_rco);
            assert(href->obj == tcp->slots[i].orig_obj);
            atomic_fetch_add_explicit(&tcp->getref_ok, 1,
              memory_order_relaxed);
            RC_DECREF(href->rco);
        }
    } while (!atomic_load_explicit(&tcp->release_done, memory_order_acquire));
    return (NULL);
}

int
main(void)
{
    struct test_ctx tc;
    pthread_t getter_id, release_id;
    int i;
    int ecode;

    memset(&tc, '\0', sizeof(tc));
    atomic_init(&tc.start, false);
    atomic_init(&tc.getter_ready, false);
    atomic_init(&tc.release_done, false);
    atomic_init(&tc.getref_ok, 0);
    atomic_init(&tc.getref_null, 0);

#if defined(_RTPP_MEMDEB_H)
    RTPP_MEMDEB_APP_INIT();
    if (rtpp_memdeb_selftest(MEMDEB_SYM) != 0) {
        return (1);
    }
#endif

    for (i = 0; i < TEST_NREFS; i++) {
        tc.slots[i].rco = rtpp_refcnt_ctor(NULL, NULL);
        assert(tc.slots[i].rco != NULL);
        tc.slots[i].orig_rco = tc.slots[i].rco;
        tc.slots[i].orig_obj = &tc.slots[i];
        tc.slots[i].wref = rtpp_wref_ctor();
        assert(tc.slots[i].wref != NULL);
        assert(CALL_SMETHOD(tc.slots[i].wref, setref, tc.slots[i].rco,
          tc.slots[i].orig_obj) == 0);
        tc.slots[i].spinval = i + 1;
        tc.slots[i].spin_budget = 1024 + ((i * 977u) % 4096);
        assert(CALL_SMETHOD(tc.slots[i].rco, attach, delay_dtor,
          &tc.slots[i]) == 0);
    }

    assert(pthread_create(&getter_id, NULL, getter_run, &tc) == 0);
    assert(pthread_create(&release_id, NULL, release_run, &tc) == 0);
    atomic_store_explicit(&tc.start, true, memory_order_release);
    pthread_join(release_id, NULL);
    pthread_join(getter_id, NULL);

    assert(atomic_load_explicit(&tc.getref_ok, memory_order_relaxed) > 0);
    for (i = 0; i < TEST_NREFS; i++) {
        assert(CALL_SMETHOD(tc.slots[i].wref, getref) == NULL);
        RTPP_OBJ_DECREF(tc.slots[i].wref);
    }

    printf("rtpp_wref_test: ok=%llu null=%llu\n",
      (unsigned long long)atomic_load_explicit(&tc.getref_ok,
        memory_order_relaxed),
      (unsigned long long)atomic_load_explicit(&tc.getref_null,
        memory_order_relaxed));
    ecode = 0;
#if defined(_RTPP_MEMDEB_H)
    if (rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) != 0) {
        ecode = 1;
    }
#endif
    return (ecode);
}
