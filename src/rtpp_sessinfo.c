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

#include <sys/stat.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

static int rtpp_sinfo_get_nsessions(struct rtpp_sessinfo_obj *);
static void rtpp_sinfo_append(struct rtpp_sessinfo_obj *, struct rtpp_session *,
  int index);

struct rtpp_sessinfo_obj *
rtpp_sessinfo_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_sessinfo_obj *sessinfo;

    sessinfo = rtpp_zmalloc(sizeof(struct rtpp_sessinfo_obj));
    if (sessinfo == NULL) {
        return (NULL);
    }
    sessinfo->sessions = rtpp_zmalloc((sizeof sessinfo->sessions[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->sessions == NULL) {
        goto e0;
    }
    sessinfo->pfds_rtp = rtpp_zmalloc((sizeof sessinfo->pfds_rtp[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->pfds_rtp == NULL) {
        goto e2;
    }
    sessinfo->pfds_rtcp = rtpp_zmalloc((sizeof sessinfo->pfds_rtcp[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->pfds_rtcp == NULL) {
        goto e3;
    }
    pthread_mutex_init(&sessinfo->lock, NULL);

    sessinfo->get_nsessions = &rtpp_sinfo_get_nsessions;
    sessinfo->append = &rtpp_sinfo_append;

    return (sessinfo);

e3:
    free(sessinfo->pfds_rtp);
e2:
    free(sessinfo->sessions);
e0:
    free(sessinfo);
    return (NULL);
}

static int
rtpp_sinfo_get_nsessions(struct rtpp_sessinfo_obj *sessinfo)
{
    int rval;

    pthread_mutex_lock(&sessinfo->lock);
    rval = sessinfo->nsessions;
    pthread_mutex_unlock(&sessinfo->lock);
    return (rval);
}

static void
rtpp_sinfo_append(struct rtpp_sessinfo_obj *sessinfo, struct rtpp_session *sp,
  int index)
{
    int rtp_index;

    pthread_mutex_lock(&sessinfo->lock);
    rtp_index = sessinfo->nsessions;
    sessinfo->sessions[rtp_index] = sp;
    sessinfo->pfds_rtp[rtp_index].fd = sp->stream[index].fd;
    sessinfo->pfds_rtp[rtp_index].events = POLLIN;
    sessinfo->pfds_rtp[rtp_index].revents = 0;
    sessinfo->pfds_rtcp[rtp_index].fd = sp->rtcp->stream[index].fd;
    sessinfo->pfds_rtcp[rtp_index].events = POLLIN;
    sessinfo->pfds_rtcp[rtp_index].revents = 0;
    sp->stream[index].sidx = rtp_index;
    sp->rtcp->stream[index].sidx = rtp_index;
    sessinfo->nsessions++;
    pthread_mutex_unlock(&sessinfo->lock);
}
