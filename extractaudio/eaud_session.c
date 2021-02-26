/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "rtpp_types.h"
#include "rtpp_ssrc.h"
#include "rtp_info.h"
#include "rtp_analyze.h"
#include "rtpa_stats.h"

#include "eaud_session.h"
#include "rtpp_loader.h"

/* Lookup session given ssrc */
struct session *
eaud_session_lookup(struct channels *channels, uint32_t ssrc, struct channel **cpp)
{
    struct cnode *cnp;

    MYQ_FOREACH(cnp, channels) {
        if (MYQ_FIRST(&(cnp->cp->session))->rpkt->ssrc == ssrc) {
            *cpp = cnp->cp;
            return &(cnp->cp->session);
        }
    }
    return NULL;
}

int
eaud_session_load(const char *path, struct channels *channels, enum origin origin,
  struct eaud_crypto *crypto)
{
    int pcount, jc;
    struct rtpp_session_stat stat;
    struct rtpa_stats_jitter jstat;
    struct rtpp_loader *loader;

    loader = rtpp_load(path);
    if (loader == NULL)
        return -1;

    if (rtpp_stats_init(&stat) < 0)
        goto e0;
    pcount = loader->load(loader, channels, &stat, origin, crypto);

    update_rtpp_totals(&stat, &stat);
    jc = get_jitter_stats(stat.jdata, &jstat, NULL);
    printf("pcount=%u, min_seq=%u, max_seq=%u, seq_offset=%u, ssrc=0x%.8X, duplicates=%u\n",
      (unsigned int)stat.last.pcount, (unsigned int)stat.last.min_seq, (unsigned int)stat.last.max_seq,
      (unsigned int)stat.last.seq_offset, (unsigned int)stat.last.ssrc.val, (unsigned int)stat.last.duplicates);
    printf("ssrc_changes=%u, psent=%u, precvd=%u, plost=%d\n", stat.ssrc_changes, stat.psent, stat.precvd,
      stat.psent - stat.precvd);
    if (jc > 0) {
        printf("last_jitter=%f,average_jitter=%f,max_jitter=%f\n",
          jstat.jlast, jstat.javg, jstat.jmax);
    }

    loader->destroy(loader);
    rtpp_stats_destroy(&stat);

    return pcount;
e0:
    loader->destroy(loader);
    return -1;
}

int
eaud_session_scan(const char *path)
{
    int pcount;
    struct rtpp_loader *loader;

    loader = rtpp_load(path);
    if (loader == NULL)
        goto e0;

    pcount = loader->scan(loader, NULL);
    loader->destroy(loader);

    return pcount;
e0:
    return -1;
}
