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

#ifndef _RTPP_QUEUE_H_
#define _RTPP_QUEUE_H_

struct rtpp_queueng;
struct rtpp_wi;

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

struct rtpp_queueng *rtpp_queueng_init(int, const char *format, ...);
void rtpp_queueng_destroy(struct rtpp_queueng *queue);

struct rtpp_queueng_hint {
    unsigned int pos;
    unsigned int gen;
};

void *rtpp_queueng_findtail(struct rtpp_queueng *queue, const struct rtpp_queueng_hint *ihp, struct rtpp_queueng_hint *ohp);
int rtpp_queueng_findhead(struct rtpp_queueng *queue, const struct rtpp_queueng_hint *ihp, struct rtpp_queueng_hint *ohp);
void *rtpp_queueng_pop(struct rtpp_queueng *queue, struct rtpp_queueng_hint *hint);
int rtpp_queueng_push(struct rtpp_queueng *queue, void *tp, struct rtpp_queueng_hint *hint);

void rtpp_queueng_put_item(struct rtpp_wi *wi, struct rtpp_queueng *);
void rtpp_queueng_pump(struct rtpp_queueng *);

struct rtpp_wi *rtpp_queueng_get_item(struct rtpp_queueng *queue, int return_on_wake);
int rtpp_queueng_get_items(struct rtpp_queueng *, struct rtpp_wi **, int, int);
int rtpp_queueng_get_length(struct rtpp_queueng *);

DEFINE_METHOD(rtpp_wi, rtpp_queueng_match_fn, int, void *);

int rtpp_queueng_count_matching(struct rtpp_queueng *, rtpp_queueng_match_fn_t, void *);
struct rtpp_wi *rtpp_queueng_get_first_matching(struct rtpp_queueng *, rtpp_queueng_match_fn_t, void *);

#endif
