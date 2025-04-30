/*
 * Copyright (c) 2014-2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_queue.h"
#include "rtpp_mallocs.h"
#include "rtpp_wi.h"
#include "rtpp_debug.h"
#include "rtpp_time.h"

#define RTPQ_DEBUG 0

typedef struct {
    unsigned int buflen;
    unsigned int head;
    unsigned int tail;
    struct rtpp_wi *buffer[0];
} circ_buf_t;

static int
circ_buf_isempty(const circ_buf_t *c)
{

    return (c->head == c->tail); /* if the head == tail, we don't have any data */
}

static int
circ_buf_push(circ_buf_t *c, struct rtpp_wi *data)
{
    unsigned int next;

    next = c->head + 1;  /* next is where head will point to after this write. */
    if (next == c->buflen)
        next = 0;

    if (next == c->tail)  /* if the head + 1 == tail, circular buffer is full */
        return(-1);

#if RTPQ_DEBUG
    assert(c->buffer[c->head] == NULL);
#endif
    c->buffer[c->head] = data;  /* Load data and then move */
    c->head = next;             /* head to next data offset. */
    return(0);  /* return success to indicate successful push. */
}

static int
circ_buf_pop(circ_buf_t *c, struct rtpp_wi **data)
{
    unsigned int next;

    if (circ_buf_isempty(c))
        return(-1);

    next = c->tail + 1;  /* next is where tail will point to after this read. */
    if (next == c->buflen)
        next = 0;
#if RTPQ_DEBUG
    assert(c->tail < c->buflen);
#endif

    *data = c->buffer[c->tail];  /* Read data and then move */
#if RTPQ_DEBUG
    c->buffer[c->tail] = NULL;
#endif
    c->tail = next;              /* tail to next offset. */
    return(0);  /* return success to indicate successful pop. */
}

static unsigned int
circ_buf_popmany(circ_buf_t *c, struct rtpp_wi *data[], unsigned int howmany)
{
    unsigned int next;
    unsigned int last;
    unsigned int copyn;
    unsigned int rval;

    rval = 0;
    RTPP_DBG_ASSERT(howmany > 0);
    while (!circ_buf_isempty(c)) {
        next = last = c->tail + howmany - rval;
        if (c->head < c->tail) {
            if (last >= c->buflen) {
                last = c->buflen;
                next = 0;
            }
        } else {
            if (last > c->head) {
                last = c->head;
                next = c->head;
            }
        }
        copyn = last - c->tail;
        memcpy(data, &(c->buffer[c->tail]), copyn * sizeof(data[0]));
#if RTPQ_DEBUG
        memset(&(c->buffer[c->tail]), '\0', copyn * sizeof(data[0]));
#endif
        c->tail = next;
        rval += copyn;
        if (rval == howmany)
            break;
        data += copyn;
    }
#if RTPQ_DEBUG
    assert(rval <= howmany);
    assert(c->tail < c->buflen);
#endif

    return(rval); /* Return number of objects popped */
}

static int
circ_buf_peek(const circ_buf_t *c, unsigned int offset, struct rtpp_wi **data)
{
    unsigned int itmidx, clen;

    if (circ_buf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + c->buflen) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    itmidx = c->tail + offset;  /* itmidx points to the item in question */
    if(itmidx >= c->buflen)
        itmidx -= c->buflen;
#if RTPQ_DEBUG
    assert(itmidx < c->buflen);
    assert(c->buffer[itmidx] != NULL);
#endif

    *data = c->buffer[itmidx];  /* Read data and then move */
    return(0);  /* return success to indicate successful pop. */
}

static int
circ_buf_replace(circ_buf_t *c, unsigned int offset, struct rtpp_wi **data)
{
    unsigned int itmidx, clen;
    struct rtpp_wi *tdata;

    if (circ_buf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + c->buflen) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    itmidx = c->tail + offset;  /* itmidx points to the item in question */
    if(itmidx >= c->buflen)
        itmidx -= c->buflen;
#if RTPQ_DEBUG
    assert(itmidx < c->buflen);
    assert(c->buffer[itmidx] != NULL);
#endif
    tdata = c->buffer[itmidx];
#if RTPQ_DEBUG
    assert(tdata != NULL);
#endif
    c->buffer[itmidx] = *data;  /* Read data and then replace */
    *data = tdata;
    return(0);  /* return success to indicate successful pop. */
}

static int
circ_buf_remove(circ_buf_t *c, unsigned int offset)
{
    unsigned int clen;
    struct rtpp_wi *data;

    if (circ_buf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + c->buflen) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    for (; offset > 0; offset--) {
        assert(circ_buf_peek(c, offset - 1, &data) == 0);
        assert(circ_buf_replace(c, offset, &data) == 0);
    }
#if RTPQ_DEBUG
    assert(c->buffer[c->tail] != NULL);
    c->buffer[c->tail] = NULL;
#endif
    c->tail += 1;
    if (c->tail == c->buflen)
        c->tail = 0;
    return(0);  /* return success to indicate successful removal. */
}

struct rtpp_queue
{
    struct rtpp_wi *head;
    struct rtpp_wi *tail;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    unsigned int length;
    unsigned int qlen;
    unsigned int mlen;
    circ_buf_t circb;
    char name[128];
};

struct rtpp_queue *
rtpp_queue_init(unsigned int cb_capacity, const char *fmt, ...)
{
    struct rtpp_queue *queue;
    unsigned int cb_buflen;
    va_list ap;
    int eval;
    pthread_condattr_t cond_attr;

    cb_buflen = cb_capacity + 1;
    queue = rtpp_zmalloc(sizeof(*queue) + (sizeof(queue->circb.buffer[0]) * cb_buflen));
    if (queue == NULL)
        goto e0;

    /* Set the clock type for the condition variable to CLOCK_MONOTONIC */
    if (pthread_condattr_init(&cond_attr) != 0) {
        goto e1;
    }
    if (pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) != 0) {
        goto e2;
    }
    if ((eval = pthread_cond_init(&queue->cond, &cond_attr)) != 0) {
        goto e2;
    }
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        goto e3;
    }
    va_start(ap, fmt);
    int r = vsnprintf(queue->name, sizeof(queue->name), fmt, ap);
    va_end(ap);
    if (r >= sizeof(queue->name)) {
        goto e4;
    }
    queue->qlen = 1;
    queue->mlen = -1;
    queue->circb.buflen = cb_buflen;
    pthread_condattr_destroy(&cond_attr);
    return (queue);
e4:
    pthread_mutex_destroy(&queue->mutex);
e3:
    pthread_cond_destroy(&queue->cond);
e2:
    pthread_condattr_destroy(&cond_attr);
e1:
    free(queue);
e0:
    return (NULL);
}

int
rtpp_queue_setmaxlen(struct rtpp_queue *queue, unsigned int new_mlen)
{

    pthread_mutex_lock(&queue->mutex);
    int mlen = queue->mlen;
    queue->mlen = new_mlen;
    pthread_mutex_unlock(&queue->mutex);
    return (mlen);
}

void
rtpp_queue_destroy(struct rtpp_queue *queue)
{
    while (rtpp_queue_get_length(queue) > 0) {
        struct rtpp_wi *wip;
        wip = rtpp_queue_get_item(queue, 0);
        RTPP_OBJ_DECREF(wip);
    }
    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->mutex);
    free(queue);
}

static int
rtpp_queue_getclen(const struct rtpp_queue *queue)
{
    int clen;

    clen = queue->length;
    if (queue->circb.head < queue->circb.tail) {
       clen += (queue->circb.head + queue->circb.buflen) - queue->circb.tail;
    } else if (queue->circb.head > queue->circb.tail) {
       clen += queue->circb.head - queue->circb.tail;
    }

    return (clen);
}

unsigned int
rtpp_queue_setqlen(struct rtpp_queue *queue, unsigned int qlen)
{
    unsigned int rval;

    pthread_mutex_lock(&queue->mutex);
    rval = queue->qlen;
    queue->qlen = qlen;
    pthread_mutex_unlock(&queue->mutex);
    return (rval);
}

int
rtpp_queue_put_item(struct rtpp_wi *wi, struct rtpp_queue *queue)
{
    int rval = 0;

    pthread_mutex_lock(&queue->mutex);
    /*
     * If queue is not empty, push to the queue so that order of elements
     * is preserved while pulling them out.
     */
    if (queue->mlen != -1 && rtpp_queue_getclen(queue) >= queue->mlen) {
        rval = -1;
        goto out;
    }
    if ((queue->length > 0) || (circ_buf_push(&queue->circb, wi) != 0)) {
        RTPPQ_APPEND(queue, wi);
#if 0
        if (queue->length > 99 && queue->length % 100 == 0)
            fprintf(stderr, "queue(%s): length %d\n", queue->name, queue->length);
#endif
    }

    if ((queue->qlen == 1) || (queue->qlen > 1 && rtpp_queue_getclen(queue) % queue->qlen == 0) || wi->wi_type == RTPP_WI_TYPE_SGNL) {
        /* notify worker thread */
        pthread_cond_signal(&queue->cond);
    }

out:
    pthread_mutex_unlock(&queue->mutex);
    return (rval);
}

void
rtpp_queue_pump(struct rtpp_queue *queue)
{

    pthread_mutex_lock(&queue->mutex);
    if (rtpp_queue_getclen(queue) > 0) {
        /* notify worker thread */
        pthread_cond_signal(&queue->cond);
    }

    pthread_mutex_unlock(&queue->mutex);
}

void
rtpp_queue_wakeup(struct rtpp_queue *queue)
{

    pthread_mutex_lock(&queue->mutex);
    /* notify worker thread */
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
}

struct rtpp_wi *
rtpp_queue_get_item_by(struct rtpp_queue *queue, struct timespec *deadline, int *rval)
{
    struct rtpp_wi *wi;

    pthread_mutex_lock(&queue->mutex);
    while (rtpp_queue_getclen(queue) == 0) {
        int rc = pthread_cond_timedwait(&queue->cond, &queue->mutex, deadline);
        if (rval != NULL)
            *rval = rc;
        pthread_mutex_unlock(&queue->mutex);
        return (NULL);
    }
#if RTPQ_DEBUG
    assert(rtpp_queue_getclen(queue) > 0);
#endif
    if (circ_buf_pop(&queue->circb, &wi) == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return (wi);
    }
    wi = queue->head;
#if RTPQ_DEBUG
    assert(rtpp_queue_getclen(queue) > 0);
#endif
    RTPPQ_REMOVE_HEAD(queue);
    pthread_mutex_unlock(&queue->mutex);
    wi->next = NULL;

    return (wi);
}

struct rtpp_wi *
rtpp_queue_get_item(struct rtpp_queue *queue, int return_on_wake)
{
    struct rtpp_wi *wi;

    pthread_mutex_lock(&queue->mutex);
    while (rtpp_queue_getclen(queue) == 0) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
        if (rtpp_queue_getclen(queue) == 0 && return_on_wake != 0) {
            pthread_mutex_unlock(&queue->mutex);
            return (NULL);
        }
    }
#if RTPQ_DEBUG
    assert(rtpp_queue_getclen(queue) > 0);
#endif
    if (circ_buf_pop(&queue->circb, &wi) == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return (wi);
    }
    wi = queue->head;
#if RTPQ_DEBUG
    assert(rtpp_queue_getclen(queue) > 0);
#endif
    RTPPQ_REMOVE_HEAD(queue);
    pthread_mutex_unlock(&queue->mutex);
    wi->next = NULL;

    return (wi);
}

int
rtpp_queue_get_items(struct rtpp_queue *queue, struct rtpp_wi **items, int ilen, int return_on_wake)
{
    int i, j;

    pthread_mutex_lock(&queue->mutex);
    while (rtpp_queue_getclen(queue) == 0) {
        pthread_cond_wait(&queue->cond, &queue->mutex);
        if (rtpp_queue_getclen(queue) == 0 && return_on_wake != 0) {
            pthread_mutex_unlock(&queue->mutex);
            return (0);
        }
    }
    /* Pull out of circular buffer first */
    i = circ_buf_popmany(&queue->circb, items, ilen);
    if ((i == ilen) || (queue->length == 0))
        goto done;
    items += i;
    ilen -= i;
    for (j = 0; j < ilen; j++) {
        items[j] = queue->head;
        queue->head = items[j]->next;
        if (queue->head == NULL) {
            queue->tail = NULL;
            j += 1;
            break;
        }
    }
    queue->length -= j;
    i += j;
done:
    pthread_mutex_unlock(&queue->mutex);

    return (i);
}

int
rtpp_queue_get_length(struct rtpp_queue *queue)
{
    int length;

    pthread_mutex_lock(&queue->mutex);
    length = rtpp_queue_getclen(queue);
    pthread_mutex_unlock(&queue->mutex);
    return (length);
}

#if 0
int
rtpp_queue_count_matching(struct rtpp_queue *queue, rtpp_queue_match_fn_t match_fn, void *fn_args)
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
#endif

struct rtpp_wi *
rtpp_queue_get_first_matching(struct rtpp_queue *queue, rtpp_queue_match_fn_t match_fn, void *fn_args)
{
    struct rtpp_wi *wi, *wi_prev;
    int i;

    pthread_mutex_lock(&queue->mutex);
    for (i = 0;; i++) {
        if (circ_buf_peek(&queue->circb, i, &wi) != 0)
            break;
        if (match_fn(wi, fn_args) == 0) {
            assert(circ_buf_remove(&queue->circb, i) == 0);
            pthread_mutex_unlock(&queue->mutex);
            return (wi);
        }
    }
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
