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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config_pp.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_codeptr.h"
#include "rtpp_mallocs.h"
#include "rtpp_stats.h"
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;

static int fail_after = -1;
static unsigned int attempts;

static void *
test_alloc(size_t size, size_t offset)
{
    attempts++;
    if (fail_after == 0)
        return NULL;
    if (fail_after > 0)
        fail_after--;
    return rtpp_rzmalloc(size, offset);
}

/* Inspect retained snapshots and inject failures without changing the API. */
#undef rtpp_rzmalloc
#define rtpp_rzmalloc(size, offset) test_alloc(size, offset)
#include "advanced/pproc_manager.c"
#undef rtpp_rzmalloc

static int
stats_getidx(struct rtpp_stats *stats, const char *name)
{
    return 0;
}

static const struct rtpp_stats_smethods test_stats_methods = {
    .getidxbyname = stats_getidx,
};

struct reader_state {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int entered, resume, visited;
};

struct handler_state {
    struct pproc_manager *manager;
    int key;
    int destroyed;
    struct reader_state *reader;
};

static void
handler_dtor(void *arg)
{
    struct handler_state *state = arg;
    struct packet_processor_if found;

    state->destroyed++;
    /* This would deadlock if snapshot references were released under lock. */
    if (state->manager != NULL)
        assert(CALL_SMETHOD(state->manager, lookup, &state->key, &found) == 0);
}

static struct pproc_handlers *
hold_snapshot(struct pproc_manager *manager)
{
    struct pproc_manager_pvt *pvt;
    struct pproc_handlers *snapshot;

    PUB2PVT(manager, pvt);
    pthread_mutex_lock(&pvt->lock);
    snapshot = pvt->handlers;
    RTPP_OBJ_INCREF(snapshot);
    pthread_mutex_unlock(&pvt->lock);
    return snapshot;
}

static void
check_snapshot(struct pproc_handlers *snapshot, struct handler_state *states,
  const int *keys, int count)
{
    assert(snapshot->nprocs == count);
    for (int i = 0; i < count; i++)
        assert(snapshot->pproc[i].ppif.key == &states[keys[i]].key);
}

static void
check_manager(struct pproc_manager *manager, struct handler_state *states,
  const int *keys, int count)
{
    struct pproc_handlers *snapshot = hold_snapshot(manager);
    struct pproc_handlers *spare = snapshot->spare;

    check_snapshot(snapshot, states, keys, count);
    for (int n = count - 1; n >= 0; n--) {
        assert(spare != NULL && spare->nprocs == n);
        for (int i = 0; i < n; i++)
            assert(spare->pproc[i].ppif.rcnt == NULL);
        spare = spare->spare;
    }
    assert(spare == NULL);
    RTPP_OBJ_DECREF(snapshot);
}

static struct pproc_act
test_enqueue(const struct pkt_proc_ctx *ctx)
{
    struct handler_state *state = ctx->pproc->arg;
    struct reader_state *reader = state->reader;

    assert(reader != NULL);
    pthread_mutex_lock(&reader->lock);
    if (state->key == 0) {
        reader->entered = 1;
        pthread_cond_signal(&reader->cond);
        while (!reader->resume)
            pthread_cond_wait(&reader->cond, &reader->lock);
    }
    assert(state->key == reader->visited++);
    pthread_mutex_unlock(&reader->lock);
    return state->key == 2 ? PPROC_ACT_TAKE : PPROC_ACT_NOP;
}

static void
register_handler(struct pproc_manager *manager, struct handler_state *state,
  enum pproc_order order)
{
    struct packet_processor_if handler = {
        .descr = "test handler",
        .key = &state->key,
        .arg = state,
        .enqueue = test_enqueue,
        .rcnt = rtpp_refcnt_ctor(state, handler_dtor),
    };
    struct pproc_handlers *before;
    int status;

    assert(handler.rcnt != NULL);
    before = hold_snapshot(manager);
    for (int failure = 0; failure < 2; failure++) {
        fail_after = failure;
        status = CALL_SMETHOD(manager, reg, order, &handler);
        fail_after = -1;
        assert(status == -1);
        struct pproc_handlers *after = hold_snapshot(manager);
        assert(after == before);
        RTPP_OBJ_DECREF(after);
        assert(state->destroyed == 0);
    }
    RTPP_OBJ_DECREF(before);
    assert(CALL_SMETHOD(manager, reg, order, &handler) == 0);
    RTPP_OBJ_DECREF(&handler);
}

static void
remove_handler(struct pproc_manager *manager, struct handler_state *state)
{
    unsigned int before = attempts;

    fail_after = 0;
    CALL_SMETHOD(manager, unreg, &state->key);
    fail_after = -1;
    assert(attempts == before);
}

static void
test_removal_orders(struct rtpp_stats *stats)
{
    static const int orders[][3] = {
        {0, 1, 2}, {0, 2, 1}, {1, 0, 2},
        {1, 2, 0}, {2, 0, 1}, {2, 1, 0}
    };
    const int original[] = {0, 1, 2};

    for (unsigned int test = 0; test < sizeof(orders) / sizeof(orders[0]); test++) {
        struct handler_state states[3] = {0};
        struct pproc_manager *manager = pproc_manager_ctor(stats, 0);
        assert(manager != NULL);
        /* Register out of priority order. */
        register_handler(manager, &states[2], PPROC_ORD_RELAY);
        register_handler(manager, &states[0], PPROC_ORD_RECV);
        register_handler(manager, &states[1], PPROC_ORD_ANALYZE);
        struct pproc_handlers *reader = hold_snapshot(manager);
        int live[] = {1, 1, 1};
        for (int step = 0; step < 3; step++) {
            int removed = orders[test][step], remaining[3], n = 0;
            states[removed].manager = manager;
            remove_handler(manager, &states[removed]);
            live[removed] = 0;
            for (int i = 0; i < 3; i++) {
                if (live[i]) remaining[n++] = i;
                assert(states[i].destroyed == 0);
            }
            check_manager(manager, states, remaining, n);
            check_snapshot(reader, states, original, 3);
            assert(reader->spare == NULL);
        }
        RTPP_OBJ_DECREF(reader);
        for (int i = 0; i < 3; i++) assert(states[i].destroyed == 1);
        RTPP_OBJ_DECREF(manager);
    }
}

static void
test_clone_and_interleaving(struct rtpp_stats *stats)
{
    struct handler_state states[4] = {0};
    struct pproc_manager *manager = pproc_manager_ctor(stats, 0), *clone;
    const int original[] = {0, 1, 2};
    const int changed[] = {0, 2, 3};

    assert(manager != NULL);
    for (int i = 0; i < 3; i++)
        register_handler(manager, &states[i], PPROC_ORD_ANALYZE);
    /* Manager + active snapshot + three spares: fail each allocation. */
    for (int failure = 0; failure < 5; failure++) {
        fail_after = failure;
        clone = CALL_SMETHOD(manager, clone);
        fail_after = -1;
        assert(clone == NULL);
        check_manager(manager, states, original, 3);
    }
    clone = CALL_SMETHOD(manager, clone);
    assert(clone != NULL);
    remove_handler(manager, &states[1]);
    register_handler(manager, &states[3], PPROC_ORD_RELAY);
    check_manager(manager, states, changed, 3);
    check_manager(clone, states, original, 3);
    RTPP_OBJ_DECREF(manager);
    assert(states[3].destroyed == 1);
    for (int i = 0; i < 3; i++) {
        assert(states[i].destroyed == 0);
        remove_handler(clone, &states[i]);
        assert(states[i].destroyed == 1);
    }
    RTPP_OBJ_DECREF(clone);

    /* Destroy a populated manager, including all of its unused spares. */
    memset(states, 0, sizeof(states));
    manager = pproc_manager_ctor(stats, 0);
    assert(manager != NULL);
    for (int i = 0; i < 4; i++)
        register_handler(manager, &states[i], PPROC_ORD_ANALYZE);
    RTPP_OBJ_DECREF(manager);
    for (int i = 0; i < 4; i++) assert(states[i].destroyed == 1);
}

static void *
reader_run(void *arg)
{
    struct pproc_manager *manager = arg;
    struct pkt_proc_ctx ctx = {0};

    assert(CALL_SMETHOD(manager, handle, &ctx) == PPROC_ACT_TAKE_v);
    return NULL;
}

static void
test_concurrent_reader(struct rtpp_stats *stats)
{
    struct handler_state states[4] = {0};
    struct reader_state reader = {0};
    struct pproc_manager *manager = pproc_manager_ctor(stats, 0);
    pthread_t thread;
    const int last[] = {3};

    assert(manager != NULL);
    assert(pthread_mutex_init(&reader.lock, NULL) == 0);
    assert(pthread_cond_init(&reader.cond, NULL) == 0);
    for (int i = 0; i < 3; i++) {
        states[i].key = i;
        states[i].reader = &reader;
        states[i].manager = manager;
        register_handler(manager, &states[i], PPROC_ORD_ANALYZE);
    }
    assert(pthread_create(&thread, NULL, reader_run, manager) == 0);
    pthread_mutex_lock(&reader.lock);
    while (!reader.entered)
        pthread_cond_wait(&reader.cond, &reader.lock);
    pthread_mutex_unlock(&reader.lock);

    /* The reader still owns [A,B,C] while the manager removes all three. */
    remove_handler(manager, &states[1]);
    remove_handler(manager, &states[0]);
    remove_handler(manager, &states[2]);
    register_handler(manager, &states[3], PPROC_ORD_ANALYZE);
    check_manager(manager, states, last, 1);
    for (int i = 0; i < 3; i++) assert(states[i].destroyed == 0);

    pthread_mutex_lock(&reader.lock);
    reader.resume = 1;
    pthread_cond_signal(&reader.cond);
    pthread_mutex_unlock(&reader.lock);
    assert(pthread_join(thread, NULL) == 0);
    assert(reader.visited == 3);
    for (int i = 0; i < 3; i++) assert(states[i].destroyed == 1);
    RTPP_OBJ_DECREF(manager);
    assert(states[3].destroyed == 1);
    pthread_cond_destroy(&reader.cond);
    pthread_mutex_destroy(&reader.lock);
}

int
main(void)
{
    struct rtpp_stats stats = {.smethods = &test_stats_methods};

    RTPP_MEMDEB_APP_INIT();
    stats.rcnt = rtpp_refcnt_ctor(NULL, NULL);
    assert(stats.rcnt != NULL);
    test_removal_orders(&stats);
    test_clone_and_interleaving(&stats);
    test_concurrent_reader(&stats);
    RC_DECREF(stats.rcnt);
    assert(rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) == 0);
    puts("pproc_manager_test: all checks passed");
    return 0;
}
