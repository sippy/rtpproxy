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

#include <sys/socket.h>
#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_time.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_pcnts_strm.h"
#include "rtpp_pcnt_strm_fin.h"
#include "rtpp_endian.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"

struct rtpp_pcnt_strm_priv {
    struct rtpp_pcnt_strm pub;
    struct rtpp_pcnts_strm cnt;
    pthread_mutex_t lock;
};

static void rtpp_pcnt_strm_dtor(struct rtpp_pcnt_strm_priv *);
static void rtpp_pcnt_strm_get_stats(struct rtpp_pcnt_strm *,
  struct rtpp_pcnts_strm *);
static void rtpp_pcnt_strm_reg_pktin(struct rtpp_pcnt_strm *,
  struct rtp_packet *);

#define PUB2PVT(pubp) \
  ((struct rtpp_pcnt_strm_priv *)((char *)(pubp) - offsetof(struct rtpp_pcnt_strm_priv, pub)))

struct rtpp_pcnt_strm *
rtpp_pcnt_strm_ctor(void)
{
    struct rtpp_pcnt_strm_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_pcnt_strm_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->pub.get_stats = &rtpp_pcnt_strm_get_stats;
    pvt->pub.reg_pktin = &rtpp_pcnt_strm_reg_pktin;
    CALL_SMETHOD(pvt->pub.rcnt, attach,
      (rtpp_refcnt_dtor_t)&rtpp_pcnt_strm_dtor, pvt);
    return ((&pvt->pub));

e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_pcnt_strm_dtor(struct rtpp_pcnt_strm_priv *pvt)
{

    rtpp_pcnt_strm_fin(&(pvt->pub));
    pthread_mutex_destroy(&pvt->lock);
    free(pvt);
}

static void
rtpp_pcnt_strm_get_stats(struct rtpp_pcnt_strm *self,
  struct rtpp_pcnts_strm *ocnt)
{
    struct rtpp_pcnt_strm_priv *pvt;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    memcpy(ocnt, &pvt->cnt, sizeof(struct rtpp_pcnts_strm));
    pthread_mutex_unlock(&pvt->lock);
}

static void
rtpp_pcnt_strm_reg_pktin(struct rtpp_pcnt_strm *self,
  struct rtp_packet *pkt)
{
    struct rtpp_pcnt_strm_priv *pvt;
    double ipi;

    pvt = PUB2PVT(self);
    pthread_mutex_lock(&pvt->lock);
    pvt->cnt.npkts_in++;
    if (pvt->cnt.first_pkt_rcv.mono == 0.0) {
        pvt->cnt.first_pkt_rcv.mono = pkt->rtime.mono;
        pvt->cnt.first_pkt_rcv.wall = pkt->rtime.wall;
    } else {
        ipi = fabs(pkt->rtime.mono - pvt->cnt.last_pkt_rcv.mono);
        if (pvt->cnt.longest_ipi < ipi) {
            pvt->cnt.longest_ipi = ipi;
        }
    }
    if (pvt->cnt.last_pkt_rcv.mono < pkt->rtime.mono) {
        pvt->cnt.last_pkt_rcv.mono = pkt->rtime.mono;
        pvt->cnt.last_pkt_rcv.wall = pkt->rtime.wall;
    }
    pthread_mutex_unlock(&pvt->lock);
}
