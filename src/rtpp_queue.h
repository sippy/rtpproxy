/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_QUEUE_H_
#define _RTPP_QUEUE_H_

struct rtpp_queue;
struct rtpp_wi;
struct timespec;

#define RTPPQ_REMOVE_HEAD(rqp) {             \
    if ((rqp)->tail == (rqp)->head) {        \
        (rqp)->tail = NULL;                  \
    }                                        \
    (rqp)->head = (rqp)->head->next;         \
    (rqp)->length -= 1;                      \
}

#define RTPPQ_REMOVE_AFTER(rqp, wip) {       \
    struct rtpp_wi *_twip;                   \
    if ((wip) == NULL) {                     \
        _twip = (rqp)->head;                 \
        RTPPQ_REMOVE_HEAD(rqp);              \
    } else if ((rqp)->tail == (wip)->next) { \
        _twip = (wip)->next;                 \
        (wip)->next = NULL;                  \
        (rqp)->tail = (wip);                 \
        (rqp)->length -= 1;                  \
    } else {                                 \
        _twip = (wip)->next;                 \
        (wip)->next = _twip->next;           \
        (rqp)->length -= 1;                  \
    }                                        \
    _twip->next = NULL;                      \
}

#define RTPPQ_APPEND(rqp, wip) {             \
    (wip)->next = NULL;                      \
    if ((rqp)->head == NULL) {               \
        (rqp)->head = (wip);                 \
        (rqp)->tail = (wip);                 \
    } else {                                 \
        (rqp)->tail->next = (wip);           \
        (rqp)->tail = (wip);                 \
    }                                        \
    (rqp)->length += 1;                      \
}

#define RTPQ_TINY_CB_LEN  4
#define RTPQ_SMALL_CB_LEN 16
#define RTPQ_MEDIUM_CB_LEN 256
#define RTPQ_LARGE_CB_LEN 1024

struct rtpp_queue *rtpp_queue_init(unsigned int, const char *format, ...);
void rtpp_queue_destroy(struct rtpp_queue *queue);

int rtpp_queue_put_item(struct rtpp_wi *wi, struct rtpp_queue *) RTPP_EXPORT;
void rtpp_queue_pump(struct rtpp_queue *);
void rtpp_queue_wakeup(struct rtpp_queue *);

struct rtpp_wi *rtpp_queue_get_item(struct rtpp_queue *queue, int return_on_wake) RTPP_EXPORT;
struct rtpp_wi *rtpp_queue_get_item_by(struct rtpp_queue *queue, struct timespec *,
  int *);
int rtpp_queue_get_items(struct rtpp_queue *, struct rtpp_wi **, int, int);
int rtpp_queue_get_length(struct rtpp_queue *);
unsigned int rtpp_queue_setqlen(struct rtpp_queue *, unsigned int);

DEFINE_METHOD(rtpp_wi, rtpp_queue_match_fn, int, void *);

int rtpp_queue_count_matching(struct rtpp_queue *, rtpp_queue_match_fn_t, void *);
struct rtpp_wi *rtpp_queue_get_first_matching(struct rtpp_queue *, rtpp_queue_match_fn_t, void *);
int rtpp_queue_setmaxlen(struct rtpp_queue *queue, unsigned int new_mlen);

#endif
