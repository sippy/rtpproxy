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
#include "rtpp_wi.h"
#include "rtpp_wi_sgnl.h"

struct rtpp_wi_sgnl {
   struct rtpp_wi pub;
   int signum;
   size_t data_len;
   char data[0];
};

static void
rtpp_wi_free_sgnl(struct rtpp_wi *wi)
{
    struct rtpp_wi_sgnl *wipp;

    PUB2PVT(wi, wipp);
    free(wipp);
}

static const struct rtpp_wi_sgnl rtpp_wi_sgnl_i = {
   .pub = {
       .dtor = rtpp_wi_free_sgnl,
       .wi_type = RTPP_WI_TYPE_SGNL
   }
};

struct rtpp_wi *
#if !defined(RTPP_CHECK_LEAKS)
rtpp_wi_malloc_sgnl(int signum, const void *data, size_t datalen)
#else
rtpp_wi_malloc_sgnl_memdeb(const char *fname, int linen, const char *funcn, int signum, const void *data, size_t datalen)
#endif
{
    struct rtpp_wi_sgnl *wipp;
#if !defined(RTPP_CHECK_LEAKS)
    wipp = malloc(sizeof(struct rtpp_wi_sgnl) + datalen);
#else
    wipp = rtpp_memdeb_malloc(sizeof(struct rtpp_wi_sgnl) + datalen,
      MEMDEB_SYM, fname, linen, funcn);
#endif
    if (wipp == NULL) {
        return (NULL);
    }
    *wipp = rtpp_wi_sgnl_i;
    wipp->signum = signum;
    if (datalen > 0) {
        wipp->data_len = datalen;
        memcpy(wipp->data, data, datalen);
    }
    return (&(wipp->pub));
}

void *
rtpp_wi_sgnl_get_data(struct rtpp_wi *wi, size_t *datalen)
{
    struct rtpp_wi_sgnl *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    PUB2PVT(wi, wipp);
    if (datalen != NULL) {
        *datalen = wipp->data_len;
    }
    return(wipp->data);
}

int
rtpp_wi_sgnl_get_signum(struct rtpp_wi *wi)
{
    struct rtpp_wi_sgnl *wipp;

    assert(wi->wi_type == RTPP_WI_TYPE_SGNL);
    PUB2PVT(wi, wipp);
    return (wipp->signum);
}
