/*
 * Copyright (c) 2023 Sippy Software, Inc., http://www.sippysoft.com
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

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"
#include "rtpp_rw_lock.h"
#include "rtpp_rw_lock_fin.h"

struct rtpp_rw_lock_priv {
    struct rtpp_rw_lock pub;
    pthread_mutex_t cnt_lock;
    pthread_mutex_t write_lock;
    int nreaders;
    int nwriters;
};

static void rtpp_rw_lock_lock(struct rtpp_rw_lock *, enum rtpp_rw_lock_mode);
static void rtpp_rw_lock_unlock(struct rtpp_rw_lock *, enum rtpp_rw_lock_mode);
static int rtpp_rw_lock_upgrade(struct rtpp_rw_lock *);

DEFINE_SMETHODS(rtpp_rw_lock,
    .lock = &rtpp_rw_lock_lock,
    .unlock = &rtpp_rw_lock_unlock,
    .upgrade = &rtpp_rw_lock_upgrade,
);

static void
rtpp_rw_lock_dtor(struct rtpp_rw_lock_priv *pvt)
{

    rtpp_rw_lock_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->write_lock);
    pthread_mutex_destroy(&pvt->cnt_lock);
}

struct rtpp_rw_lock *
rtpp_rw_lock_ctor(void)
{
    struct rtpp_rw_lock_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL)
        goto e1;
    if (pthread_mutex_init(&pvt->cnt_lock, NULL) != 0)
        goto e2;
    if (pthread_mutex_init(&pvt->write_lock, NULL) != 0)
        goto e3;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_rw_lock_dtor);
    return ((&pvt->pub));
e3:
    pthread_mutex_destroy(&pvt->cnt_lock);
e2:
    RTPP_OBJ_DECREF(&pvt->pub);
e1:
    return (NULL);
}

static void
rtpp_rw_lock_lock(struct rtpp_rw_lock *self, enum rtpp_rw_lock_mode mode)
{
    struct rtpp_rw_lock_priv *pvt;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->cnt_lock);
    if (mode == RTPP_RW_LOCK_RD) {
        pvt->nreaders += 1;
        if (pvt->nreaders == 1)
            pthread_mutex_lock(&pvt->write_lock);
    } else {
        pvt->nwriters += 1;
    }
    pthread_mutex_unlock(&pvt->cnt_lock);
    if (mode == RTPP_RW_LOCK_WR)
        pthread_mutex_lock(&pvt->write_lock);
}

static void
rtpp_rw_lock_unlock(struct rtpp_rw_lock *self, enum rtpp_rw_lock_mode mode)
{
    struct rtpp_rw_lock_priv *pvt;

    PUB2PVT(self, pvt);
    if (mode == RTPP_RW_LOCK_WR)
        pthread_mutex_unlock(&pvt->write_lock);
    pthread_mutex_lock(&pvt->cnt_lock);
    if (mode == RTPP_RW_LOCK_RD) {
        pvt->nreaders -= 1;
        if (pvt->nreaders == 0)
            pthread_mutex_unlock(&pvt->write_lock);
    } else {
        pvt->nwriters -= 1;
    }
    pthread_mutex_unlock(&pvt->cnt_lock);
}

static int
rtpp_rw_lock_upgrade(struct rtpp_rw_lock *self)
{
    struct rtpp_rw_lock_priv *pvt;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->cnt_lock);
    if (pvt->nwriters > 0 || pvt->nreaders > 1) {
        pthread_mutex_unlock(&pvt->cnt_lock);
        return (-1);
    }
    pvt->nreaders = 0;
    pvt->nwriters = 1;
    pthread_mutex_unlock(&pvt->cnt_lock);
    return (0);
}
