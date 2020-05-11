/*
 * Copyright (c) 2019-2020 Sippy Software, Inc., http://www.sippysoft.com
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
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_module.h"
#include "rtpp_module_wthr.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_refcnt.h"
#include "rtpp_cfg.h"
#include "rtpp_wi.h"
#include "rtpp_wi_sgnl.h"
#include "rtpp_wi_data.h"
#include "rtpp_queue.h"
#include "rtpp_stream.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_notify.h"
#include "rtpp_timeout_data.h"

struct rtpp_module_priv {
    struct rtpp_notify *notifier;
};

struct catch_dtmf_einfo {
    int pending;
    char digit;
    uint32_t ts;
    uint16_t duration;
};

#define EINFO_HST_DPTH 4

struct catch_dtmf_edata {
    struct rtpp_refcnt *rcnt;
    struct catch_dtmf_einfo hst[EINFO_HST_DPTH];
    int hst_next;
    enum rtpp_stream_side side;
};

struct catch_dtmf_stream_cfg {
    atomic_int pt;
    struct catch_dtmf_edata *edata;
    const struct rtpp_timeout_data *rtdp;
};

static struct rtpp_module_priv *rtpp_catch_dtmf_ctor(const struct rtpp_cfg *);
static void rtpp_catch_dtmf_dtor(struct rtpp_module_priv *);
static void rtpp_catch_dtmf_worker(const struct rtpp_wthrdata *);

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

struct rtpp_minfo rtpp_module = {
    .descr.name = "catch_dtmf",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 3,
    .proc.ctor = rtpp_catch_dtmf_ctor,
    .proc.dtor = rtpp_catch_dtmf_dtor,
    .wapi = &(const struct rtpp_wthr_handlers){.main_thread = rtpp_catch_dtmf_worker},
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM
#endif
};

static void
rtpp_catch_dtmf_edata_dtor(void *p)
{

    mod_free(p);
}

static struct catch_dtmf_edata *
rtpp_catch_dtmf_edata_ctor(enum rtpp_stream_side side)
{
    struct catch_dtmf_edata *edata;
    int i;

    edata = mod_rzmalloc(sizeof(*edata), offsetof(struct catch_dtmf_edata, rcnt));
    if (edata == NULL) {
        goto e0;
    }
    for (i = 0; i < EINFO_HST_DPTH; i++) {
        edata->hst[i].digit = -1;
    }
    edata->side = side;
    CALL_SMETHOD(edata->rcnt, attach, rtpp_catch_dtmf_edata_dtor, edata);
    return edata;
e0:
    return (NULL);
}

struct wipkt {
    const struct rtp_packet *pkt;
    struct catch_dtmf_edata *edata;
    const struct rtpp_timeout_data *rtdp;
};

struct rtp_dtmf_event {
    unsigned int event:8;        /* event_id - digit */
#if BYTE_ORDER == BIG_ENDIAN
    unsigned int end:1;            /* indicates the end of the event */
    unsigned int res:1;            /* reserved - should be 0 */
    unsigned int volume:6;        /* volume */
#else
    unsigned int volume:6;        /* volume */
    unsigned int res:1;            /* reserved - should be 0 */
    unsigned int end:1;            /* indicates the end of the event */
#endif
    unsigned int duration:16;    /* duration */
} __attribute__((__packed__));

#define RTPP_MAX_NOTIFY_BUF 512
static const char *notyfy_type = "DTMF";

static void
rtpp_catch_dtmf_worker(const struct rtpp_wthrdata *wp)
{
    struct rtpp_module_priv *pvt;
    struct rtpp_wi *wi;
    struct wipkt *wip;
    char buf[RTPP_MAX_NOTIFY_BUF];
    const char dtmf_events[] = "0123456789*#ABCD ";
    struct catch_dtmf_einfo *eip, ei;
    int i;

    pvt = wp->mpvt;
    for (;;) {
        wi = rtpp_queue_get_item(wp->mod_q, 0);
        if (wi == wp->sigterm) {
            break;
        }
        wip = rtpp_wi_data_get_ptr(wi, sizeof(*wip), sizeof(*wip));

        struct rtp_dtmf_event *dtmf =
            (struct rtp_dtmf_event *)(wip->pkt->data.buf + sizeof(rtp_hdr_t));
        if (dtmf->event > sizeof(dtmf_events) - 1) {
            RTPP_LOG(rtpp_module.log, RTPP_LOG_DBUG, "Unhandled DTMF event %u", dtmf->event);
            goto skip;
        }
        ei.digit = dtmf_events[dtmf->event];
        ei.ts = ntohl(wip->pkt->data.header.ts);
        ei.duration = ntohs(dtmf->duration);
        eip = NULL;
        for (i = 1; i <= EINFO_HST_DPTH; i++) {
            int j = wip->edata->hst_next - i;
            if (j < 0)
                j = EINFO_HST_DPTH + j;
            if (wip->edata->hst[j].ts == ei.ts && wip->edata->hst[j].digit != -1) {
                eip = &wip->edata->hst[j];
                break;
            }
        }

        if (eip == NULL) {
            /* this is a new event */
            eip = &wip->edata->hst[wip->edata->hst_next];
            eip->ts = ei.ts;
            eip->pending = 1;
            eip->digit = ei.digit;
            eip->duration = ei.duration;
            wip->edata->hst_next += 1;
            if (wip->edata->hst_next == EINFO_HST_DPTH)
                wip->edata->hst_next = 0;
            goto skip;
        }
        if (!eip->pending) {
            if (!dtmf->end && eip->duration <= ei.duration)
                RTPP_LOG(rtpp_module.log, RTPP_LOG_WARN, "Received DTMF for %c without "
                        "start %d", ei.digit, eip->pending);
            goto skip;
        }

        if (ei.digit != eip->digit) {
            RTPP_LOG(rtpp_module.log, RTPP_LOG_WARN, "Received DTMF for %c "
                    "while processing %c", ei.digit, eip->digit);
            goto skip;
        }
        if (eip->duration < ei.duration)
            eip->duration = ei.duration;

        if (!dtmf->end)
            goto skip;
        /* we received the end of the DTMF */
        /* all good - send the notification */
        eip->pending = 0;
        snprintf(buf, RTPP_MAX_NOTIFY_BUF, "%s %c %u %u %d",
          wip->rtdp->notify_tag, ei.digit, dtmf->volume, eip->duration,
          (wip->edata->side == RTPP_SSIDE_CALLER) ? 0 : 1);
        CALL_METHOD(pvt->notifier, schedule, wip->rtdp->notify_target, buf,
          notyfy_type);

skip:
        CALL_SMETHOD(wip->edata->rcnt, decref);
        CALL_SMETHOD(wip->rtdp->rcnt, decref);
        CALL_SMETHOD(wip->pkt->rcnt, decref);
        CALL_METHOD(wi, dtor);
    }
}

static struct rtpp_module_priv *
rtpp_catch_dtmf_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->notifier = cfsp->rtpp_notify_cf;
    return (pvt);

#if 0
e1:
    mod_free(pvt);
#endif
e0:
    return (NULL);
}

static void
rtpp_catch_dtmf_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}
