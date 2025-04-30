/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <sys/time.h>
#include <sys/resource.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_nofile.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

struct rtpp_nofile_pvt {
    struct rtpp_nofile pub;
    struct rlimit limit_storage;
};

static void
rtpp_nofile_dtor(struct rtpp_nofile *pub)
{
    struct rtpp_nofile_pvt *priv;

    PUB2PVT(pub, priv);
    free(priv);
}

struct rtpp_nofile *
rtpp_nofile_ctor(void)
{
    struct rtpp_nofile_pvt *priv;

    priv = rtpp_zmalloc(sizeof(*priv));
    if (priv == NULL)
        return (NULL);
    if (getrlimit(RLIMIT_NOFILE, &(priv->limit_storage)) != 0)
        err(1, "getrlimit");
    atomic_init(&(priv->pub.warned), 0);
    priv->pub.dtor = rtpp_nofile_dtor;
    priv->pub.limit = &(priv->limit_storage);
    return (&(priv->pub));
}

long long
rtpp_rlim_max(const struct rtpp_nofile *np)
{

    return (long long)(np->limit->rlim_max);
}
