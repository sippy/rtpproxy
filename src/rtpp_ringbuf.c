/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_ringbuf.h"
#include "rtpp_ringbuf_fin.h"
#include "rtpp_util.h"

struct rtpp_ringbuf_priv
{
    struct rtpp_ringbuf pub;
    void *elements;
    int nelements;
    size_t el_size;
    int c_elem;
    int b_full;
    void *rco[0];
};

static void rtpp_ringbuf_dtor(struct rtpp_ringbuf_priv *);
static void rtpp_ringbuf_push(struct rtpp_ringbuf *, void *);
static int rtpp_ringbuf_locate(struct rtpp_ringbuf *, void *);

#define PUB2PVT(pubp)      ((struct rtpp_ringbuf_priv *)((char *)(pubp) - \
  offsetof(struct rtpp_ringbuf_priv, pub)))

struct rtpp_ringbuf *
rtpp_ringbuf_ctor(size_t el_size, int nelements)
{
    struct rtpp_ringbuf_priv *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_ringbuf_priv) + rtpp_refcnt_osize());
    if (pvt == NULL) {
        goto e0;
    }
    pvt->elements = rtpp_zmalloc(el_size * nelements);
    if (pvt->elements == NULL) {
        goto e1;
    }
    pvt->el_size = el_size;
    pvt->nelements = nelements;
    pvt->pub.rcnt = rtpp_refcnt_ctor_pa(&pvt->rco[0], pvt,
      (rtpp_refcnt_dtor_t)&rtpp_ringbuf_dtor);
    if (pvt->pub.rcnt == NULL) {
        goto e2;
    }
    pvt->pub.push = rtpp_ringbuf_push;
    pvt->pub.locate = rtpp_ringbuf_locate;
    return (&pvt->pub);
e2:
    free(pvt->elements);
e1:
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_ringbuf_dtor(struct rtpp_ringbuf_priv *pvt)
{

    rtpp_ringbuf_fin(&(pvt->pub));
    free(pvt->elements);
    free(pvt);
}

static void
rtpp_ringbuf_push(struct rtpp_ringbuf *self, void *data)
{
    struct rtpp_ringbuf_priv *pvt;
    void *dp;

    pvt = PUB2PVT(self);
    dp = (char *)pvt->elements + (pvt->el_size * pvt->c_elem);
    memcpy(dp, data, pvt->el_size);
    pvt->c_elem++;
    if (pvt->c_elem == pvt->nelements) {
        if (pvt->b_full == 0) {
            pvt->b_full = 1;
        }
        pvt->c_elem = 0;
    }
}

static int
rtpp_ringbuf_locate(struct rtpp_ringbuf *self, void *data)
{
    struct rtpp_ringbuf_priv *pvt;
    int i, last_el;
    void *dp;

    pvt = PUB2PVT(self);
    last_el = (pvt->b_full != 0) ? pvt->nelements : pvt->c_elem;
    for (i = 0; i < last_el; i++) {
        dp = (char *)pvt->elements + (pvt->el_size * i);
        if (memcmp(dp, data, pvt->el_size) == 0) {
            return (i);
        }
    }
    return (-1);
}
