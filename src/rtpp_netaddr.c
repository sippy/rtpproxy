/*
 * Copyright (c) 2016 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"
#include "rtpp_netaddr.h"
#include "rtpp_netaddr_fin.h"
#include "rtpp_network.h"
#include "rtpp_debug.h"

struct rtpp_netaddr_priv {
    struct rtpp_netaddr pub;
    struct sockaddr_storage sas;
    socklen_t rlen;
    pthread_mutex_t lock;
};

static void rtpp_netaddr_set(struct rtpp_netaddr *, const struct sockaddr *, size_t);
static void rtpp_netaddr_dtor(struct rtpp_netaddr_priv *);
static void rtpp_netaddr_set(struct rtpp_netaddr *, const struct sockaddr *, size_t);
static int rtpp_netaddr_isempty(struct rtpp_netaddr *);
static int rtpp_netaddr_cmp(struct rtpp_netaddr *, const struct sockaddr *, size_t);
static int rtpp_netaddr_isaddrseq(struct rtpp_netaddr *, const struct sockaddr *);
static int rtpp_netaddr_cmphost(struct rtpp_netaddr *, const struct sockaddr *);
static void rtpp_netaddr_copy(struct rtpp_netaddr *, struct rtpp_netaddr *);
static size_t rtpp_netaddr_get(struct rtpp_netaddr *, struct sockaddr *, size_t);
static size_t rtpp_netaddr_sip_print(struct rtpp_netaddr *, char *, size_t,
  char);

#define PUB2PVT(pubp) \
  ((struct rtpp_netaddr_priv *)((char *)(pubp) - offsetof(struct rtpp_netaddr_priv, pub)))

static const struct rtpp_netaddr_smethods rtpp_netaddr_smethods = {
    .set = &rtpp_netaddr_set,
    .isempty = &rtpp_netaddr_isempty,
    .cmp = &rtpp_netaddr_cmp,
    .isaddrseq = &rtpp_netaddr_isaddrseq,
    .cmphost = &rtpp_netaddr_cmphost,
    .copy = &rtpp_netaddr_copy,
    .get = &rtpp_netaddr_get,
    .sip_print = &rtpp_netaddr_sip_print
};

struct rtpp_netaddr *
rtpp_netaddr_ctor(void)
{
    struct rtpp_netaddr_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_netaddr_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->pub.smethods = &rtpp_netaddr_smethods;
    CALL_SMETHOD(pvt->pub.rcnt, attach,
      (rtpp_refcnt_dtor_t)&rtpp_netaddr_dtor, pvt);
    return ((&pvt->pub));

e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_netaddr_set(struct rtpp_netaddr *self, const struct sockaddr *addr, size_t alen)
{
    struct rtpp_netaddr_priv *pvt;

    pvt = PUB2PVT(self);
    RTPP_DBG_ASSERT(alen <= sizeof(pvt->sas));

    pthread_mutex_lock(&pvt->lock);
    memcpy(&pvt->sas, addr, alen);
    pvt->rlen = alen;
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_netaddr_dtor(struct rtpp_netaddr_priv *pvt)
{

    rtpp_netaddr_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static int
rtpp_netaddr_isempty(struct rtpp_netaddr *self)
{
    struct rtpp_netaddr_priv *pvt;
    int rval;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    rval = (pvt->rlen == 0);
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static int
rtpp_netaddr_cmp(struct rtpp_netaddr *self, const struct sockaddr *sap, size_t salen)
{
    struct rtpp_netaddr_priv *pvt;
    int rval;

    pvt = PUB2PVT(self);
    RTPP_DBG_ASSERT(salen <= sizeof(pvt->sas));
    pthread_mutex_lock(&pvt->lock);
    if (salen != pvt->rlen) {
        rval = -1;
        goto unlock_and_return;
    }
    rval = memcmp(&pvt->sas, sap, salen);
unlock_and_return:
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static int
rtpp_netaddr_isaddrseq(struct rtpp_netaddr *self, const struct sockaddr *sap)
{
    struct rtpp_netaddr_priv *pvt;
    int rval;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    RTPP_DBG_ASSERT(pvt->rlen > 0);
    rval = isaddrseq(sstosa(&pvt->sas), sap);
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static int
rtpp_netaddr_cmphost(struct rtpp_netaddr *self, const struct sockaddr *sap)
{
    struct rtpp_netaddr_priv *pvt;
    int rval;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    RTPP_DBG_ASSERT(pvt->rlen > 0);
    rval = ishostseq(sstosa(&pvt->sas), sap);
    pthread_mutex_unlock(&pvt->lock);
    return (rval);
}

static void
rtpp_netaddr_copy(struct rtpp_netaddr *self, struct rtpp_netaddr *other)
{
    struct sockaddr_storage tmp;
    socklen_t rlen;

    rlen = CALL_SMETHOD(other, get, sstosa(&tmp), sizeof(tmp));
    rtpp_netaddr_set(self, sstosa(&tmp), rlen);
}

static size_t
rtpp_netaddr_get(struct rtpp_netaddr *self, struct sockaddr *sap, size_t salen)
{
    struct rtpp_netaddr_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    RTPP_DBG_ASSERT((salen >= pvt->rlen) && (pvt->rlen > 0));
    memcpy(sap, &pvt->sas, pvt->rlen);
    pthread_mutex_unlock(&pvt->lock);
    return (pvt->rlen);
}

static size_t
rtpp_netaddr_sip_print(struct rtpp_netaddr *self, char *buf, size_t blen,
  char portsep)
{
    char *rval;
    struct rtpp_netaddr_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    RTPP_DBG_ASSERT(pvt->rlen > 0);
    rval = addrport2char_r(sstosa(&pvt->sas), buf, blen, portsep);
    pthread_mutex_unlock(&pvt->lock);
    RTPP_DBG_ASSERT(rval != NULL);
    return (strlen(rval));
}
