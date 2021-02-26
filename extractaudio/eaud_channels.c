/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2021 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "rtp_info.h"
#include "rtpp_record_adhoc.h"

#include "eaud_channels.h"
#include "eaud_session.h"

/* Insert channel keeping them ordered by time of first packet arrival */
int
channel_insert(struct channels *channels, struct channel *channel)
{
    struct cnode *cnp, *nnp;

    nnp = malloc(sizeof(*nnp));
    if (nnp == NULL)
        return (-1);
    memset(nnp, 0, sizeof(*nnp));
    nnp->cp = channel;

    MYQ_FOREACH_REVERSE(cnp, channels)
        if (MYQ_FIRST(&(cnp->cp->session))->pkt->time <
          MYQ_FIRST(&(channel->session))->pkt->time) {
            MYQ_INSERT_AFTER(channels, cnp, nnp);
            return 0;
        }
    MYQ_INSERT_HEAD(channels, nnp);
    return 0;
}

void
channel_remove(struct channels *channels, struct cnode *cnp)
{

    MYQ_REMOVE(channels, cnp);
    free(cnp);
}
