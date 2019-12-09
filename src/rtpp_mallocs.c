/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_debug.h"
#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"

void *
#if !defined(RTPP_CHECK_LEAKS)
rtpp_zmalloc(size_t msize)
#else
rtpp_zmalloc_memdeb(size_t msize, void *memdeb_p, const char *fname,
  int linen, const char *funcn)
#endif
{
    void *rval;

#if !defined(RTPP_CHECK_LEAKS)
    rval = malloc(msize);
#else
    rval = rtpp_memdeb_malloc(msize, memdeb_p, fname, linen, funcn);
#endif
    if (rval != NULL) {
        memset(rval, '\0', msize);
    }
    return (rval);
}

struct alig_help {
    char a[1];
    intmax_t b;
};

#define PpP(p1, p2, type) (type)(((char *)p1) + ((size_t)p2))

void *
#if !defined(RTPP_CHECK_LEAKS)
rtpp_rzmalloc(size_t msize, size_t rcntp_offs)
#else
rtpp_rzmalloc_memdeb(const char *fname, int linen, const char *funcn,
  size_t msize, size_t rcntp_offs)
#endif
{
    void *rval;
    struct rtpp_refcnt *rcnt;
    size_t pad_size, asize;
    void *rco;

    RTPP_DBG_ASSERT(msize >= rcntp_offs + sizeof(struct rtpp_refcnt *));
    if (offsetof(struct alig_help, b) > 1) {
        pad_size = msize % offsetof(struct alig_help, b);
        if (pad_size != 0) {
            pad_size = offsetof(struct alig_help, b) - pad_size;
        }
    } else {
        pad_size = 0;
    }
    asize = msize + pad_size + rtpp_refcnt_osize();
#if !defined(RTPP_CHECK_LEAKS)
    rval = malloc(asize);
#else
    rval = rtpp_memdeb_malloc(asize, MEMDEB_SYM, fname, linen, funcn);
#endif
    if (rval == NULL) {
        return (NULL);
    }
    memset(rval, '\0', asize);
    rco = (char *)rval + msize + pad_size;
    rcnt = rtpp_refcnt_ctor_pa(rco);
    if (rcnt == NULL) {
        goto e1;
    }
    *PpP(rval, rcntp_offs, struct rtpp_refcnt **) = rcnt;

    return (rval);
e1:
    free(rval);
    return (NULL);
}
