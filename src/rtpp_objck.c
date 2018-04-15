/*
 * Copyright (c) 2017 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <stdlib.h>

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#include "rtpp_util.h"
#else
#include "rtpp_util.h"
#endif

#include "rtpp_types.h"
#include "rtpp_memdeb_internal.h"
#include "rtpp_refcnt.h"
#include "rtpp_stats.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"

RTPP_MEMDEB_STATIC(rtpp_objck);

static enum rtpp_timed_cb_rvals
update_derived_stats(double dtime, void *argp)
{
    struct rtpp_stats *rtpp_stats;

    rtpp_stats = (struct rtpp_stats *)argp;
    CALL_SMETHOD(rtpp_stats, update_derived, dtime);
    return (CB_MORE);
}

int
main(int argc, char **argv)
{
    int ecode;
    struct rtpp_stats *rsp;
    struct rtpp_timed *rtp;
    struct rtpp_timed_task *ttp;

    RTPP_MEMDEB_INIT(rtpp_objck);
    if (rtpp_memdeb_selftest(_rtpp_objck_memdeb) != 0) {
        errx(1, "MEMDEB self-test has failed");
        /* NOTREACHED */
    }
    rtp = rtpp_timed_ctor(0.1);
    rsp = rtpp_stats_ctor();
    ttp = CALL_SMETHOD(rtp, schedule_rc, 1.0, rsp->rcnt, update_derived_stats, NULL, rsp);
    CALL_SMETHOD(ttp->rcnt, decref);
    CALL_SMETHOD(rsp->rcnt, decref);
    CALL_SMETHOD(rtp, shutdown);
    CALL_SMETHOD(rtp->rcnt, decref);

    ecode = rtpp_memdeb_dumpstats(_rtpp_objck_memdeb, 0) == 0 ? 0 : 1;

    exit(ecode);
}
