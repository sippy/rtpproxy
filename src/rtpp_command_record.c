/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdint.h>
#include <string.h>

#include "rtpp_defines.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_command.h"
#include "rtpp_command_private.h"
#include "rtpp_command_copy.h"
#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_session.h"

struct record_ematch_arg {
    int nrecorded;
    const char *from_tag;
    const char *to_tag;
    int record_single_file;
    struct cfg *cf;
};

static int
rtpp_cmd_record_ematch(void *dp, void *ap)
{
    struct rtpp_session *spa;
    int idx;
    struct record_ematch_arg *rep;

    spa = (struct rtpp_session *)dp;
    rep = (struct record_ematch_arg *)ap;

    if (compare_session_tags(spa->tag, rep->from_tag, NULL) != 0) {
        idx = 1;
    } else if (rep->to_tag != NULL &&
      (compare_session_tags(spa->tag, rep->to_tag, NULL)) != 0) {
        idx = 0;
    } else {
        return(RTPP_HT_MATCH_CONT);
    }
    if (handle_copy(rep->cf, spa, idx, NULL, rep->record_single_file) == 0) {
        rep->nrecorded++;
    }
    return(RTPP_HT_MATCH_CONT);
}

int
handle_record(struct cfg *cf, struct common_cmd_args *ccap,
  int record_single_file)
{
    struct record_ematch_arg rea;

    memset(&rea, '\0', sizeof(rea));
    rea.from_tag = ccap->from_tag;
    rea.to_tag = ccap->to_tag;
    rea.record_single_file = record_single_file;
    rea.cf = cf;
    CALL_METHOD(cf->stable->sessions_ht, foreach_key, ccap->call_id,
      rtpp_cmd_record_ematch, &rea);
    if (rea.nrecorded == 0) {
        return -1;
    }
    return 0;
}
