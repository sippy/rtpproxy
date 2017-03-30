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

#include <stdint.h>
#include <stdlib.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_notify.h"
#include "rtpp_session.h"
#include "rtpp_stats.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_proc_ttl.h"
#include "rtpp_pipe.h"

struct foreach_args {
    struct rtpp_notify *rtpp_notify_cf;
    struct rtpp_stats *rtpp_stats;
    struct rtpp_weakref_obj *sessions_wrt;
};  

static int
rtpp_proc_ttl_foreach(void *dp, void *ap)
{
    struct foreach_args *fap;
    struct rtpp_session *sp;

    fap = (struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (struct rtpp_session *)dp;

    if (CALL_METHOD(sp->rtp, get_ttl) == 0) {
        RTPP_LOG(sp->log, RTPP_LOG_INFO, "session timeout");
        if (sp->timeout_data.notify_target != NULL) {
            CALL_METHOD(fap->rtpp_notify_cf, schedule,
              sp->timeout_data.notify_target, sp->timeout_data.notify_tag);
        }
        CALL_METHOD(fap->rtpp_stats, updatebyname, "nsess_timeout", 1);
        CALL_METHOD(fap->sessions_wrt, unreg, sp->seuid);
        return (RTPP_HT_MATCH_DEL);
    } else {
        CALL_METHOD(sp->rtp, decr_ttl);
    }
    return (RTPP_HT_MATCH_CONT);
}

void
rtpp_proc_ttl(struct rtpp_hash_table *sessions_ht, struct rtpp_weakref_obj
  *sessions_wrt, struct rtpp_notify *rtpp_notify_cf, struct rtpp_stats
  *rtpp_stats)
{
    struct foreach_args fargs;

    fargs.rtpp_notify_cf = rtpp_notify_cf;
    fargs.rtpp_stats = rtpp_stats;
    fargs.sessions_wrt = sessions_wrt;
    CALL_METHOD(sessions_ht, foreach, rtpp_proc_ttl_foreach, &fargs);
}
