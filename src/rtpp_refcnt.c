/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"

struct rtpp_refcnt_priv
{
    struct rtpp_refcnt_obj pub;
    int64_t cnt;
    pthread_mutex_t cnt_lock;
    rtpp_refcnt_free_t free_f;
    void *data;
};

static void rtpp_refcnt_incref(struct rtpp_refcnt_obj *);
static void rtpp_refcnt_decref(struct rtpp_refcnt_obj *);
static void *rtpp_refcnt_getdata(struct rtpp_refcnt_obj *);

struct rtpp_refcnt_obj *
rtpp_refcnt_ctor(void *data, rtpp_refcnt_free_t free_f)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = malloc(sizeof(struct rtpp_refcnt_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    memset(pvt, '\0', sizeof(struct rtpp_refcnt_priv));
    if (pthread_mutex_init(&pvt->cnt_lock, NULL) != 0) {
        free(pvt);
        return (NULL);
    }
    pvt->data = data;
    if (free_f != NULL) {
        pvt->free_f = free_f;
    } else {
        pvt->free_f = free;
    }
    pvt->pub.incref = rtpp_refcnt_incref;
    pvt->pub.decref = rtpp_refcnt_decref;
    pvt->pub.getdata = rtpp_refcnt_getdata;
    pvt->cnt = 1;
    return (&pvt->pub);
}

static void
rtpp_refcnt_incref(struct rtpp_refcnt_obj *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    pthread_mutex_lock(&pvt->cnt_lock);
    assert(pvt->cnt > 0);
    pvt->cnt += 1;
    pthread_mutex_unlock(&pvt->cnt_lock);
}

static void
rtpp_refcnt_decref(struct rtpp_refcnt_obj *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    pthread_mutex_lock(&pvt->cnt_lock);
    pvt->cnt -= 1;
    if (pvt->cnt == 0) {
        pvt->free_f(pvt->data);
        pthread_mutex_unlock(&pvt->cnt_lock);
        pthread_mutex_destroy(&pvt->cnt_lock);
        free(pvt);
        return;
    }
    assert(pvt->cnt > 0);
    pthread_mutex_unlock(&pvt->cnt_lock);
}

static void *
rtpp_refcnt_getdata(struct rtpp_refcnt_obj *pub)
{
    struct rtpp_refcnt_priv *pvt;

    pvt = (struct rtpp_refcnt_priv *)pub;
    assert(pvt->cnt > 0);
    return (pvt->data);
}
