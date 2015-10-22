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

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_refcnt.h"
#include "rtpp_notify.h"
#include "rtpp_session.h"
#include "rtpp_stats.h"
#include "rtpp_stream.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_ttl.h"
#include "rtpp_proc_ttl.h"

struct foreach_args {
    struct rtpp_notify_obj *rtpp_notify_cf;
    struct rtpp_stats_obj *rtpp_stats;
};  

static int
rtpp_proc_ttl_foreach(void *dp, void *ap)
{
    struct foreach_args *fap;
    struct rtpp_session_obj *sp;

    fap = (struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (struct rtpp_session_obj *)dp;

    if (get_ttl(sp) == 0) {
        RTPP_LOG(sp->log, RTPP_LOG_INFO, "session timeout");
        if (sp->timeout_data.notify_target != NULL) {
            CALL_METHOD(fap->rtpp_notify_cf, schedule,
              sp->timeout_data.notify_target, sp->timeout_data.notify_tag);
        }
#if 0
        remove_session(cf, sp);
#endif
        CALL_METHOD(fap->rtpp_stats, updatebyname, "nsess_timeout", 1);
        CALL_METHOD(sp->rcnt, decref);
        return (RTPP_WR_MATCH_DEL);
    } else {
        CALL_METHOD(sp->stream[0]->ttl, decr);
        CALL_METHOD(sp->stream[1]->ttl, decr);
    }
    CALL_METHOD(sp->rcnt, decref);
    return (RTPP_WR_MATCH_CONT);
}

void
rtpp_proc_ttl(struct rtpp_weakref_obj *sessions_wrt,
  struct rtpp_notify_obj *rtpp_notify_cf, struct rtpp_stats_obj *rtpp_stats)
{
    struct foreach_args fargs;

    fargs.rtpp_notify_cf = rtpp_notify_cf;
    fargs.rtpp_stats = rtpp_stats;
    CALL_METHOD(sessions_wrt, foreach, rtpp_proc_ttl_foreach,
      &fargs);
}
