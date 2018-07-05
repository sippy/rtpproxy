/*
 * Copyright (c) 2014-2018 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
/* Apparently needed for vasprintf(3) */
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "rtpp_types.h"
#include "rtpp_queueng.h"
#include "rtpp_mallocs.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"

#define FLS_EMPTY 0x0
#define FLS_FILLD 0x1
#define FLS_RSVED 0x2

struct rtpp_qfields {
    unsigned int flags:2;
    unsigned int obff:16;
    unsigned int gen:32;
} fields;


union rtpp_qitem {
    struct rtpp_qfields fields;
    atomic_uintmax_t aval;
    uintmax_t val;
};

struct rtpp_queueng
{
    struct rtpp_wi *head;
    struct rtpp_wi *tail;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    int length;
    char *name;
    int qlen;
    union rtpp_qitem *rbuffer;
    void **pbuffer;
};

struct rtpp_queueng *
rtpp_queueng_init(int qlen, const char *fmt, ...)
{
    struct rtpp_queueng *queue;
    va_list ap;
    int eval, i;
    union rtpp_qitem ival;

    queue = rtpp_zmalloc(sizeof(*queue));
    if (queue == NULL)
        goto e0;
    queue->qlen = qlen;
    if ((eval = pthread_cond_init(&queue->cond, NULL)) != 0) {
        goto e1;
    }
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        goto e2;
    }
    va_start(ap, fmt);
    vasprintf(&queue->name, fmt, ap);
    va_end(ap);
    if (queue->name == NULL) {
        goto e3;
    }
    queue->rbuffer = rtpp_zmalloc(qlen * sizeof(union rtpp_qitem));
    if (queue->rbuffer == NULL) {
        goto e4;
    }
    queue->pbuffer = rtpp_zmalloc(qlen * sizeof(void *));
    if (queue->pbuffer == NULL) {
        goto e5;
    }
    for (i = 0; i < qlen; i++) {
        ival.val = 0;
        ival.fields.obff = i;
        ival.fields.flags = FLS_EMPTY;
        queue->rbuffer[i].aval = ATOMIC_VAR_INIT(ival.val);
    }
    return (queue);

e5:
    free(queue->rbuffer);
e4:
    free(queue->name);
e3:
    pthread_mutex_destroy(&queue->mutex);
e2:
    pthread_cond_destroy(&queue->cond);
e1:
    free(queue);
e0:
    return (NULL);
}

void
rtpp_queueng_destroy(struct rtpp_queueng *queue)
{

    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->mutex);
    free(queue->pbuffer);
    free(queue->rbuffer);
    free(queue->name);
    free(queue);
}

void
rtpp_queueng_put_item(struct rtpp_wi *wi, struct rtpp_queueng *queue)
{

    pthread_mutex_lock(&queue->mutex);
    RTPPQ_APPEND(queue, wi);
#if 0
    if (queue->length > 99 && queue->length % 100 == 0)
        fprintf(stderr, "queue(%s): length %d\n", queue->name, queue->length);
#endif

    if ((queue->qlen > 0 && queue->length % queue->qlen == 0) || wi->wi_type == RTPP_WI_TYPE_SGNL) {
        /* notify worker thread */
        pthread_cond_signal(&queue->cond);
    }

    pthread_mutex_unlock(&queue->mutex);
}

void
rtpp_queueng_pump(struct rtpp_queueng *queue)
{

    pthread_mutex_lock(&queue->mutex);
    if (queue->length > 0) {
        /* notify worker thread */
        pthread_cond_signal(&queue->cond);
    }

    pthread_mutex_unlock(&queue->mutex);
}

#define RQN_NEXT_IDX(rqnp, idx) (idx < (rqnp->qlen - 1) ? idx + 1 : 0)

void *
rtpp_queueng_findtail(struct rtpp_queueng *queue, const struct rtpp_queueng_hint *ihp, struct rtpp_queueng_hint *ohp)
{
    union rtpp_qitem cval;
    unsigned int i, j, gen, maxi;
    void *rvp;

    j = ihp->pos;
    assert(j < queue->qlen);
    gen = ihp->gen;
    maxi = queue->qlen * 2;
    for (i = 0; i < maxi; i++) {
restart:
        do {
            cval.val = atomic_load(&queue->rbuffer[j].aval);
        } while (cval.fields.flags == FLS_RSVED);
#if 0
        if ((i == 0) && ((gen < cval.fields.gen - 1) || (gen > cval.fields.gen + 1))) {
            gen = cval.fields.gen - 1;
            j = 0;
            maxi += queue->qlen;
            goto restart;
        }
#endif
        if (cval.fields.gen == gen && cval.fields.flags != FLS_FILLD)
            return (NULL);
        if (cval.fields.gen == (gen + 1) && cval.fields.flags == FLS_FILLD) {
            rvp = queue->pbuffer[cval.fields.obff];
            ohp->pos = RQN_NEXT_IDX(queue, j);
            if (ohp->pos < j) {
                ohp->gen = gen + 1;
            } else {
                ohp->gen = gen;
            }
            return (rvp);
        }
        j = RQN_NEXT_IDX(queue, j);
        if (j == 0)
            gen++;
    }
    return (NULL);
}

int
rtpp_queueng_findhead(struct rtpp_queueng *queue, const struct rtpp_queueng_hint *ihp, struct rtpp_queueng_hint *ohp)
{
    union rtpp_qitem cval;
    unsigned int i, j, gen, maxi;

    j = ihp->pos;
    assert(j < queue->qlen);
    gen = ihp->gen;
    maxi = queue->qlen * 2;
    for (i = 0; i < maxi; i++) {
restart:
        do {
            cval.val = atomic_load(&queue->rbuffer[j].aval);
        } while (cval.fields.flags == FLS_RSVED);
#if 0
        if ((i == 0) && ((gen < cval.fields.gen - 1) || (gen > cval.fields.gen + 1))) {
            gen = cval.fields.gen - 1;
            j = 0;
            maxi += queue->qlen;
            goto restart;
        }
#endif
        if (cval.fields.gen == gen && cval.fields.flags != FLS_EMPTY)
             return (-1);
        if (cval.fields.gen == gen && cval.fields.flags == FLS_EMPTY) {
            ohp->pos = RQN_NEXT_IDX(queue, j);
            if (ohp->pos < j) {
                ohp->gen = gen + 1;
            } else {
                ohp->gen = gen;
            }
            return (0);
        }
        j = RQN_NEXT_IDX(queue, j);
        if (j == 0)
            gen++;
    }
    return (-1);
}

void *
rtpp_queueng_pop(struct rtpp_queueng *queue, struct rtpp_queueng_hint *hint)
{
    union rtpp_qitem cval, nval;
    unsigned int i, j;
    void *rvp;

    assert(hint->pos < queue->qlen);
    for (i = 0, j = hint->pos; i < queue->qlen; i++) {
        cval.val = atomic_load(&queue->rbuffer[j].aval);
        if (cval.fields.gen == hint->gen && cval.fields.flags != FLS_FILLD)
            return (NULL);
        if (cval.fields.gen == (hint->gen + 1) && cval.fields.flags == FLS_FILLD) {
            nval.val = cval.val;
            nval.fields.flags = FLS_RSVED;
            if (!atomic_compare_exchange_strong(&queue->rbuffer[j].aval, &cval.val, nval.val))
                goto next;
            atomic_thread_fence(memory_order_acquire);
            rvp = queue->pbuffer[cval.fields.obff];
            nval.fields.flags = FLS_EMPTY;
            atomic_store(&queue->rbuffer[j].aval, nval.val);
            hint->pos = RQN_NEXT_IDX(queue, j);
            if (hint->pos < j) {
                hint->gen++;
            }
            return (rvp);
        }
next:
        j = RQN_NEXT_IDX(queue, j);
        if (j == 0)
            hint->gen++;
    }
    hint->pos = j;
    return (NULL);
}

int
rtpp_queueng_push(struct rtpp_queueng *queue, void *tp, struct rtpp_queueng_hint *hint)
{
    union rtpp_qitem cval, nval;
    unsigned int i, j;

    assert(hint->pos < queue->qlen);
    for (i = 0, j = hint->pos; i < queue->qlen; i++) {
        cval.val = atomic_load(&queue->rbuffer[j].aval);
        if (cval.fields.gen == hint->gen && cval.fields.flags != FLS_EMPTY)
             return (-1);
        if (cval.fields.gen == hint->gen && cval.fields.flags == FLS_EMPTY) {
            nval.val = cval.val;
            nval.fields.flags = FLS_RSVED;
            if (!atomic_compare_exchange_strong(&queue->rbuffer[j].aval, &cval.val, nval.val))
                goto next;
            queue->pbuffer[cval.fields.obff] = tp;
            atomic_thread_fence(memory_order_release);
            nval.fields.flags = FLS_FILLD;
            nval.fields.gen++;
            atomic_store(&queue->rbuffer[j].aval, nval.val);
            hint->pos = RQN_NEXT_IDX(queue, j);
            if (hint->pos < j) {
                hint->gen++;
            }
            return (0);
        }
next:
        j = RQN_NEXT_IDX(queue, j);
        if (j == 0)
            hint->gen++;
    }
    hint->pos = j;
    return (-1);
}

struct rtpp_wi *
rtpp_queueng_get_item(struct rtpp_queueng *queue, int return_on_wake)
{
    struct rtpp_wi *wi;

    pthread_mutex_lock(&queue->mutex);
    while (queue->head == NULL) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
        if (queue->head == NULL && return_on_wake != 0) {
            pthread_mutex_unlock(&queue->mutex);
            return (NULL);
        }
    }
    wi = queue->head;
    RTPPQ_REMOVE_HEAD(queue);
    pthread_mutex_unlock(&queue->mutex);
    wi->next = NULL;

    return (wi);
}

int
rtpp_queueng_get_items(struct rtpp_queueng *queue, struct rtpp_wi **items, int ilen, int return_on_wake)
{
    int i;

    pthread_mutex_lock(&queue->mutex);
    while (queue->head == NULL) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
        if (queue->head == NULL && return_on_wake != 0) {
            pthread_mutex_unlock(&queue->mutex);
            return (0);
        }
    }
    for (i = 0; i < ilen; i++) {
        items[i] = queue->head;
        queue->head = items[i]->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
            i += 1;
            break;
        }
    }
    queue->length -= i;
    pthread_mutex_unlock(&queue->mutex);

    return (i);
}

int
rtpp_queueng_get_length(struct rtpp_queueng *queue)
{
    int length;

    pthread_mutex_lock(&queue->mutex);
    length = queue->length;
    pthread_mutex_unlock(&queue->mutex);
    return (length);
}

int
rtpp_queueng_count_matching(struct rtpp_queueng *queue, rtpp_queueng_match_fn_t match_fn, void *fn_args)
{
    struct rtpp_wi *wi;
    int mcnt;

    mcnt = 0;
    pthread_mutex_lock(&queue->mutex);
    for (wi = queue->head; wi != NULL; wi = wi->next) {
        if (match_fn(wi, fn_args) == 0) {
            mcnt++;
        }
    }
    pthread_mutex_unlock(&queue->mutex);
    return (mcnt);
}

struct rtpp_wi *
rtpp_queueng_get_first_matching(struct rtpp_queueng *queue, rtpp_queueng_match_fn_t match_fn, void *fn_args)
{
    struct rtpp_wi *wi, *wi_prev;

    pthread_mutex_lock(&queue->mutex);
    wi_prev = NULL;
    for (wi = queue->head; wi != NULL; wi_prev = wi, wi = wi->next) {
        if (match_fn(wi, fn_args) == 0) {
            RTPPQ_REMOVE_AFTER(queue, wi_prev);
            pthread_mutex_unlock(&queue->mutex);
            return (wi);
        }
    }
    pthread_mutex_unlock(&queue->mutex);
    return (NULL);
}
