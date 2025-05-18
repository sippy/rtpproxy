/*
 * Copyright (c) 2019-2020 Sippy Software, Inc., http://www.sippysoft.com
 * Copyright (c) 2019 Maxim Sobolev <sobomax@sippysoft.com>
 * Copyright (c) 2019 Razvan Crainea <razvan@opensips.org>
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
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_module.h"
#include "rtpp_module_wthr.h"
#include "rtpp_module_cplane.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_codeptr.h"
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
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_util.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_linker_set.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

struct rtpp_module_priv {
    struct rtpp_notify *notifier;
    struct rtpp_minfo *mself;
};

struct catch_dtmf_einfo {
    int pending;
    int digit;
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
    struct rtpp_refcnt *rcnt;
    _Atomic(int) pt;
    _Atomic(enum pproc_action) act;
    struct catch_dtmf_edata *edata;
    const struct rtpp_timeout_data *rtdp;
    struct rtpp_minfo *mself;
};

static struct rtpp_module_priv *rtpp_catch_dtmf_ctor(const struct rtpp_cfg *,
  struct rtpp_minfo *);
static void rtpp_catch_dtmf_dtor(struct rtpp_module_priv *);
static void rtpp_catch_dtmf_worker(const struct rtpp_wthrdata *);
static int rtpp_catch_dtmf_handle_command(struct rtpp_module_priv *,
  const struct rtpp_subc_ctx *);
static int rtp_packet_is_dtmf(struct pkt_proc_ctx *);
static struct pproc_act rtpp_catch_dtmf_enqueue(const struct pkt_proc_ctx *);

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

const struct rtpp_minfo RTPP_MOD_SELF = {
    .descr.name = "catch_dtmf",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 3,
    .proc.ctor = rtpp_catch_dtmf_ctor,
    .proc.dtor = rtpp_catch_dtmf_dtor,
    .wapi = &(const struct rtpp_wthr_handlers){
        .main_thread = rtpp_catch_dtmf_worker,
        .queue_size = RTPQ_MEDIUM_CB_LEN,
    },
    .capi = &(const struct rtpp_cplane_handlers){.ul_subc_handle = rtpp_catch_dtmf_handle_command},
    .fn = &(struct rtpp_minfo_fset){0},
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM
#endif
};
#if defined(LIBRTPPROXY)
DATA_SET(rtpp_modules, RTPP_MOD_SELF);
#endif

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
            RTPP_OBJ_DECREF(wi);
            break;
        }
        wip = rtpp_wi_data_get_ptr(wi, sizeof(*wip), sizeof(*wip));

        struct rtp_dtmf_event *dtmf =
            (struct rtp_dtmf_event *)(wip->pkt->data.buf + sizeof(rtp_hdr_t));
        if (dtmf->event > sizeof(dtmf_events) - 1) {
            RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "Unhandled DTMF event %u", dtmf->event);
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
                RTPP_LOG(pvt->mself->log, RTPP_LOG_WARN, "Received DTMF for %c without "
                        "start %d", ei.digit, eip->pending);
            goto skip;
        }

        if (ei.digit != eip->digit) {
            RTPP_LOG(pvt->mself->log, RTPP_LOG_WARN, "Received DTMF for %c "
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
        rtpp_str_const_t notify_tag = {.s = buf};
        notify_tag.len = snprintf(buf, RTPP_MAX_NOTIFY_BUF, "%.*s %c %u %u %d",
          FMTSTR(wip->rtdp->notify_tag), ei.digit, dtmf->volume, eip->duration,
          (wip->edata->side == RTPP_SSIDE_CALLER) ? 0 : 1);
        CALL_METHOD(pvt->notifier, schedule, wip->rtdp->notify_target,
          rtpp_str_fix(&notify_tag), notyfy_type);

skip:
        RTPP_OBJ_DECREF(wi);
    }
}

static struct catch_dtmf_stream_cfg *
catch_dtmf_data_ctor(const struct rtpp_subc_ctx *ctxp, const rtpp_str_t *dtmf_tag,
  int new_pt, struct rtpp_minfo *mself)
{
    struct catch_dtmf_stream_cfg *rtps_c;

    rtps_c = mod_rzmalloc(sizeof(*rtps_c), offsetof(struct catch_dtmf_stream_cfg, rcnt));
    if (rtps_c == NULL) {
        goto e0;
    }
    rtps_c->mself = mself;
    RC_INCREF(mself->super_rcnt);
    RTPP_OBJ_DTOR_ATTACH_RC(rtps_c, mself->super_rcnt);
    rtps_c->edata = rtpp_catch_dtmf_edata_ctor(ctxp->strmp_in->side);
    if (!rtps_c->edata) {
        RTPP_LOG(mself->log, RTPP_LOG_ERR, "cannot create edata (sp=%p)",
          ctxp->strmp_in);
        goto e1;
    }
    RTPP_OBJ_DTOR_ATTACH_RC(rtps_c, rtps_c->edata->rcnt);
    rtps_c->rtdp = rtpp_timeout_data_ctor(ctxp->sessp->timeout_data->notify_target,
      dtmf_tag);
    if (rtps_c->rtdp == NULL) {
        goto e1;
    }
    RTPP_OBJ_DTOR_ATTACH_RC(rtps_c, rtps_c->rtdp->rcnt);
    atomic_init(&(rtps_c->pt), new_pt);
    atomic_init(&(rtps_c->act), PPROC_ACT_TEE_v);
    return (rtps_c);
e1:
    RTPP_OBJ_DECREF(rtps_c);
e0:
    return (NULL);
}

static int
rtpp_catch_dtmf_handle_command(struct rtpp_module_priv *pvt,
  const struct rtpp_subc_ctx *ctxp)
{
    struct catch_dtmf_stream_cfg *rtps_c;
    int len;
    int old_pt, new_pt = 101;
    enum pproc_action old_act, new_act = PPROC_ACT_TEE_v;
    rtpp_str_const_t dtmf_tag;

    if (ctxp->sessp->timeout_data == NULL) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "notification is not enabled (sp=%p)",
          ctxp->sessp);
        return (-1);
    }
    if (ctxp->subc_args->c < 2) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "no tag specified (sp=%p)",
          ctxp->sessp);
        return (-1);
    }

    if (ctxp->subc_args->c > 4) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "too many arguments (sp=%p)",
          ctxp->sessp);
        return (-1);
    }

    dtmf_tag = ctxp->subc_args->v[1];
    char *l_dtmf_tag = alloca(dtmf_tag.len + 1);
    len = url_unquote2(dtmf_tag.s, l_dtmf_tag, dtmf_tag.len);
    if (len == -1) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "syntax error: invalid URL "
          "encoding");
        return (-1);
    }
    l_dtmf_tag[len] = '\0';
    dtmf_tag.s = l_dtmf_tag;
    dtmf_tag.len = len;

    if (ctxp->subc_args->c > 2) {
        if (atoi_saferange(ctxp->subc_args->v[2].s, &new_pt, 0, 127)) {
            RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "syntax error: invalid "
              "payload type: %.*s", FMTSTR(&ctxp->subc_args->v[2]));
            return (-1);
        }
        if (ctxp->subc_args->c > 3) {
            for (const char *opt = ctxp->subc_args->v[3].s; *opt != '\0'; opt++) {
                switch (*opt) {
                case 'h':
                case 'H':
                    new_act = PPROC_ACT_DROP_v;
                    break;

                default:
                    RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "syntax error: "
                      "invalid modifier: \"%c\"", *opt);
                    return (-1);
                }
            }
        }
    }

    struct packet_processor_if dtmf_poi;

    if (CALL_SMETHOD(ctxp->strmp_in->pproc_manager, lookup, pvt, &dtmf_poi) == 0) {
        rtps_c = catch_dtmf_data_ctor(ctxp, rtpp_str_fix(&dtmf_tag), new_pt, pvt->mself);
        if (rtps_c == NULL) {
            return (-1);
        }
        dtmf_poi = (struct packet_processor_if) {
            .descr = "dtmf",
            .taste = rtp_packet_is_dtmf,
            .enqueue = rtpp_catch_dtmf_enqueue,
            .key = pvt,
            .arg = rtps_c,
            .rcnt = rtps_c->rcnt
        };
        if (CALL_SMETHOD(ctxp->strmp_in->pproc_manager, reg, PPROC_ORD_WITNESS, &dtmf_poi) < 0) {
            RTPP_OBJ_DECREF(&dtmf_poi);
            return (-1);
        }
    } else {
        rtps_c = dtmf_poi.arg;
    }

    old_pt = atomic_exchange(&(rtps_c->pt), new_pt);
    if (old_pt != -1)
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "sp=%p, pt=%d->%d",
          ctxp->strmp_in, old_pt, new_pt);
    old_act = atomic_exchange(&(rtps_c->act), new_act);
    if (old_act != new_act)
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "sp=%p, act=%d->%d",
          ctxp->strmp_in, old_act, new_act);
    RTPP_OBJ_DECREF(&dtmf_poi);
    return (0);
}

static int
rtp_packet_is_dtmf(struct pkt_proc_ctx *pktx)
{
    struct catch_dtmf_stream_cfg *rtps_c;

    if (pktx->strmp_in->pipe_type != PIPE_RTP)
        return (0);
    rtps_c = pktx->pproc->arg;
    if (atomic_load(&(rtps_c->pt)) != pktx->pktp->data.header.pt)
        return (0);
    pktx->auxp = rtps_c;

    return (1);
}

static struct pproc_act
rtpp_catch_dtmf_enqueue(const struct pkt_proc_ctx *pktx)
{
    struct rtpp_wi *wi;
    struct wipkt *wip;
    struct catch_dtmf_stream_cfg *rtps_c;

    rtps_c = (struct catch_dtmf_stream_cfg *)pktx->auxp;
    /* we duplicate the tag to make sure it does not vanish */
    wi = rtpp_wi_malloc_udata((void **)&wip, sizeof(struct wipkt));
    if (wi == NULL)
        return (PPROC_ACT_DROP);
    RTPP_OBJ_BORROW(wi, pktx->pktp);
    /* we need to duplicate the tag and state */
    wip->edata = rtps_c->edata;
    RTPP_OBJ_BORROW(wi, rtps_c->edata);
    wip->pkt = pktx->pktp;
    RTPP_OBJ_BORROW(wi, rtps_c->rtdp);
    wip->rtdp = rtps_c->rtdp;
    if (rtpp_queue_put_item(wi, rtps_c->mself->wthr.mod_q) != 0) {
        RTPP_OBJ_DECREF(wi);
        return (PPROC_ACT_DROP);
    }
    return (PPROC_ACT(atomic_load(&(rtps_c->act))));
}

static struct rtpp_module_priv *
rtpp_catch_dtmf_ctor(const struct rtpp_cfg *cfsp, struct rtpp_minfo *mself)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->notifier = cfsp->rtpp_notify_cf;
    pvt->mself = mself;
    return (pvt);

e0:
    return (NULL);
}

static void
rtpp_catch_dtmf_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}
