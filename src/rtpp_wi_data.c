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

#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_wi.h"
#include "rtpp_wi_data.h"

struct rtpp_wi_data {
   struct rtpp_wi pub;
   size_t data_len;
   char data[0];
};

struct rtpp_wi *
rtpp_wi_malloc_data(void *dataptr, size_t datalen)
{
    struct rtpp_wi_data *wipp;

    wipp = rtpp_rmalloc(sizeof(struct rtpp_wi_data) + datalen, PVT_RCOFFS(wipp));
    if (wipp == NULL) {
        return (NULL);
    }
    *wipp = (const struct rtpp_wi_data) {
        .pub.wi_type = RTPP_WI_TYPE_DATA,
        .pub.rcnt = wipp->pub.rcnt
    };
    if (datalen > 0) {
        wipp->data_len = datalen;
        memcpy(wipp->data, dataptr, datalen);
    }
    return (&(wipp->pub));
}

struct rtpp_wi *
rtpp_wi_malloc_udata(void **dataptr, size_t datalen)
{
    struct rtpp_wi_data *wipp;

    wipp = rtpp_rmalloc(sizeof(struct rtpp_wi_data) + datalen, PVT_RCOFFS(wipp));
    if (wipp == NULL) {
        return (NULL);
    }
    *wipp = (const struct rtpp_wi_data) {
        .pub.wi_type = RTPP_WI_TYPE_DATA,
        .pub.rcnt = wipp->pub.rcnt
    };
    if (datalen > 0) {
        wipp->data_len = datalen;
        *dataptr = wipp->data;
    }
    return (&(wipp->pub));
}

void *
rtpp_wi_data_get_ptr(struct rtpp_wi *wi, size_t min_len, size_t max_len)
{
    struct rtpp_wi_data *wipp;

    RTPP_DBG_ASSERT(wi->wi_type == RTPP_WI_TYPE_DATA);
    PUB2PVT(wi, wipp);
    RTPP_DBG_ASSERT(wipp->data_len >= min_len);
    RTPP_DBG_ASSERT(max_len == 0 || wipp->data_len <= max_len);

    return(wipp->data);
}
