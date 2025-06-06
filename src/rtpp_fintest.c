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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_linker_set.h"

#ifdef RTPP_CHECK_LEAKS
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif


SET_DECLARE(rtpp_fintests, const void);

int _naborts = 0;

typedef void (*fintest_t) (void);

int
rtpp_fintest()
{
    const void **tp;

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_APP_INIT();
#endif

    SET_FOREACH(tp, rtpp_fintests) {
        ((fintest_t)*tp)();
    }
    assert(_naborts > 0);

#if defined(RTPP_CHECK_LEAKS)
    int ecode = rtpp_memdeb_dumpstats(MEMDEB_SYM, 0) == 0 ? 0 : 1;
#else
    int ecode = 0;
#endif

    return (ecode);
}
