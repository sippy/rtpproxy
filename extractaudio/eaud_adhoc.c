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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>

#include "config.h"

#if HAVE_ERR_H
# include <err.h>
#endif

#include "rtp.h"
#include "rtpp_record_adhoc.h"
#include "eaud_adhoc.h"

int
eaud_adhoc_dissect(unsigned char *bp, size_t blen,
  struct adhoc_dissect  *adp)
{
    unsigned char *ep;
    struct pkt_hdr_adhoc *pkt;

    ep = bp + blen;
    for (adp->nextcp = bp; adp->nextcp < ep; adp->nextcp += pkt->plen) {
        pkt = (struct pkt_hdr_adhoc *)adp->nextcp;
        adp->nextcp += sizeof(*pkt);
        if (pkt->plen < sizeof(rtp_hdr_t))
            continue;
        if (adp->nextcp + pkt->plen > ep) {
            warnx("input file truncated, %ld bytes are missing",
              (long)(adp->nextcp + pkt->plen - ep));
            return (ADH_DSCT_TRNK);
        }
        adp->ahp = pkt;
        adp->pkt = adp->nextcp;
        adp->nextcp += pkt->plen;
        return (ADH_DSCT_OK);
    }
    return (ADH_DSCT_EOF);
}
