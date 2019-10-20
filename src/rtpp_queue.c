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

#include <sys/types.h>
#include <sys/socket.h>

#include "rtpp_types.h"
#include "rtpp_queue.h"
#include "rtpp_mallocs.h"
#include "rtpp_wi.h"
#include "rtpp_wi_private.h"

#define CB_CAPACITY (1 * 1024)
#define CB_BUFLEN  (CB_CAPACITY + 1)

#define RTPQ_DEBUG 0

typedef struct {
    int head;
    int tail;
    int buflen;
    struct rtpp_wi *buffer[CB_BUFLEN];
} circ_bbuf_t;

static int
circ_bbuf_isempty(const circ_bbuf_t *c)
{

    return (c->head == c->tail); // if the head == tail, we don't have any data
}

static int
circ_bbuf_push(circ_bbuf_t *c, struct rtpp_wi *data)
{
    int next;

    next = c->head + 1;  // next is where head will point to after this write.
    if (next == CB_BUFLEN)
        next = 0;

    if (next == c->tail)  // if the head + 1 == tail, circular buffer is full
        return(-1);

#ifdef RTPQ_DEBUG
    assert(c->buffer[c->head] == NULL);
#endif
    c->buffer[c->head] = data;  // Load data and then move
    c->head = next;             // head to next data offset.
    return(0);  // return success to indicate successful push.
}

static int
circ_bbuf_pop(circ_bbuf_t *c, struct rtpp_wi **data)
{
    int next;

    if (circ_bbuf_isempty(c))
        return(-1);

    next = c->tail + 1;  // next is where tail will point to after this read.
    if (next == CB_BUFLEN)
        next = 0;
#ifdef RTPQ_DEBUG
    assert(c->tail >= 0 && c->tail < CB_BUFLEN);
#endif

    *data = c->buffer[c->tail];  // Read data and then move
#ifdef RTPQ_DEBUG
    c->buffer[c->tail] = NULL;
#endif
    c->tail = next;              // tail to next offset.
    return(0);  // return success to indicate successful pop.
}

static int
circ_bbuf_peek(const circ_bbuf_t *c, int offset, struct rtpp_wi **data)
{
    int itmidx, clen;

    if (circ_bbuf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + CB_BUFLEN) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    itmidx = c->tail + offset;  // itmidx points to the item in question
    if(itmidx >= CB_BUFLEN)
        itmidx -= CB_BUFLEN;
#ifdef RTPQ_DEBUG
    assert(itmidx >= 0 && itmidx < CB_BUFLEN);
    assert(c->buffer[itmidx] != NULL);
#endif

    *data = c->buffer[itmidx];  // Read data and then move
    return(0);  // return success to indicate successful pop.
}

static int
circ_bbuf_replace(circ_bbuf_t *c, int offset, struct rtpp_wi **data)
{
    int itmidx, clen;
    struct rtpp_wi *tdata;

    if (circ_bbuf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + CB_BUFLEN) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    itmidx = c->tail + offset;  // itmidx points to the item in question
    if(itmidx >= CB_BUFLEN)
        itmidx -= CB_BUFLEN;
#ifdef RTPQ_DEBUG
    assert(itmidx >= 0 && itmidx < CB_BUFLEN);
    assert(c->buffer[itmidx] != NULL);
#endif
    tdata = c->buffer[itmidx];
#ifdef RTPQ_DEBUG
    assert(tdata != NULL);
#endif
    c->buffer[itmidx] = *data;  // Read data and then replace
    *data = tdata;
    return(0);  // return success to indicate successful pop.
}

static int
circ_bbuf_remove(circ_bbuf_t *c, int offset)
{
    int clen;
    struct rtpp_wi *data;

    if (circ_bbuf_isempty(c))
        return(-1);

    if (c->head < c->tail) {
       clen = (c->head + CB_BUFLEN) - c->tail;
    } else {
       clen = c->head - c->tail;
    }
    if (offset >= clen)
        return(-1);

    for (; offset > 0; offset--) {
        assert(circ_bbuf_peek(c, offset - 1, &data) == 0);
        assert(circ_bbuf_replace(c, offset, &data) == 0);
    }
#ifdef RTPQ_DEBUG
    assert(c->buffer[c->tail] != NULL);
    c->buffer[c->tail] = NULL;
#endif
    c->tail += 1;
    if (c->tail == CB_BUFLEN)
        c->tail = 0;
    return(0);  // return success to indicate successful removal.
}

struct rtpp_queue
{
    struct rtpp_wi *head;
    struct rtpp_wi *tail;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    int length;
    char *name;
    int qlen;
    circ_bbuf_t circb;
};

struct rtpp_queue *
rtpp_queue_init(int qlen, const char *fmt, ...)
{
    struct rtpp_queue *queue;
    va_list ap;
    int eval;

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
    queue->circb.buflen = CB_BUFLEN;
    return (queue);
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
rtpp_queue_destroy(struct rtpp_queue *queue)
{

    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->mutex);
    free(queue->name);
    free(queue);
}

static int
rtpp_queue_getclen(const struct rtpp_queue *queue)
{
    int clen;

    clen = queue->length;
    if (queue->circb.head < queue->circb.tail) {
       clen += (queue->circb.head + CB_BUFLEN) - queue->circb.tail;
    } else if (queue->circb.head > queue->circb.tail) {
       clen += queue->circb.head - queue->circb.tail;
    }

    return (clen);
}

void
rtpp_queue_put_item(struct rtpp_wi *wi, struct rtpp_queue *queue)
{

    pthread_mutex_lock(&queue->mutex);
    /*
     * If queue is not empty, push to the queue so that order of elements
     * is preserved while pulling them out.
     */
    if ((queue->length > 0) || (circ_bbuf_push(&queue->circb, wi) != 0)) {
        RTPPQ_APPEND(queue, wi);
#if 0
        if (queue->length > 99 && queue->length % 100 == 0)
            fprintf(stderr, "queue(%s): length %d\n", queue->name, queue->length);
#endif
    }

    if ((queue->qlen > 0 && rtpp_queue_getclen(queue) % queue->qlen == 0) || wi->wi_type == RTPP_WI_TYPE_SGNL) {
        /* notify worker thread */
        pthread_cond_signal(&queue->cond);
    }

    pthread_mutex_unlock(&queue->mutex);
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
#ifdef RTPQ_DEBUG
    assert(rtpp_queue_getclen(queue) > 0);
#endif
    if (circ_bbuf_pop(&queue->circb, &wi) == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return (wi);
    }
    wi = queue->head;
#ifdef RTPQ_DEBUG
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
    for (i = 0; i < ilen; i++) {
        if (circ_bbuf_pop(&queue->circb, &items[i]) != 0)
            break;
    }
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
        if (circ_bbuf_peek(&queue->circb, i, &wi) != 0)
            break;
        if (match_fn(wi, fn_args) == 0) {
            assert(circ_bbuf_remove(&queue->circb, i) == 0);
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
