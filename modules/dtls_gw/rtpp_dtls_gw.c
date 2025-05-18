/*
 * Copyright (c) 2022 Sippy Software, Inc., http://www.sippysoft.com
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <srtp2/srtp.h>

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
#include "rtpp_packetops.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_util.h"
#include "rtpp_socket.h"
#include "rtpp_sessinfo.h"
#include "rtpp_session.h"
#include "rtpp_stats.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_proc_async.h"
#include "rtpp_ttl.h"
#include "rtpp_util.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_linker_set.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

#include "rtpp_dtls.h"
#include "rtpp_dtls_util.h"
#include "rtpp_dtls_conn.h"

struct rtpp_module_priv {
    struct rtpp_dtls *dtls_ctx;
    const struct rtpp_cfg *cfsp;
    struct rtpp_minfo *mself;
};

struct dtls_gw_stream_cfg {
    struct rtpp_refcnt *rcnt;
    struct rtpp_dtls_conn *dtls_conn;
    struct rtpp_minfo *mself;
};

enum rtpp_dtls_dir {
    DTLS_IN, SRTP_IN, RTP_OUT
};

struct rtpp_dtls_gw_aux {
    enum rtpp_dtls_dir direction;
    struct rtpp_dtls_conn *dtls_conn;
    struct rtpp_minfo *mself;
};

struct wipkt {
    struct pkt_proc_ctx pktx;
    struct rtpp_dtls_gw_aux edata;
};

static struct rtpp_module_priv *rtpp_dtls_gw_ctor(const struct rtpp_cfg *,
  struct rtpp_minfo *);
static void rtpp_dtls_gw_dtor(struct rtpp_module_priv *);
static void rtpp_dtls_gw_worker(const struct rtpp_wthrdata *);
static int rtpp_dtls_gw_handle_command(struct rtpp_module_priv *,
  const struct rtpp_subc_ctx *);
static int rtpp_dtls_gw_taste_encrypted(struct pkt_proc_ctx *);
static int rtpp_dtls_gw_taste_plain(struct pkt_proc_ctx *);
static struct pproc_act rtpp_dtls_gw_enqueue(const struct pkt_proc_ctx *);

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

const struct rtpp_minfo RTPP_MOD_SELF = {
    .descr.name = "dtls_gw",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 4,
    .proc.ctor = rtpp_dtls_gw_ctor,
    .proc.dtor = rtpp_dtls_gw_dtor,
    .wapi = &(const struct rtpp_wthr_handlers){
        .main_thread = rtpp_dtls_gw_worker,
        .queue_size = RTPQ_MEDIUM_CB_LEN,
    },
    .capi = &(const struct rtpp_cplane_handlers){.ul_subc_handle = rtpp_dtls_gw_handle_command},
    .fn = &(struct rtpp_minfo_fset){0},
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM
#endif
};
#if defined(LIBRTPPROXY)
DATA_SET(rtpp_modules, RTPP_MOD_SELF);
#endif

static void
rtpp_dtls_gw_worker(const struct rtpp_wthrdata *wp)
{
    struct rtpp_wi *wi;
    struct wipkt *wip;
    struct res_loc res;

    for (;;) {
        wi = rtpp_queue_get_item(wp->mod_q, 0);
        if (wi == wp->sigterm) {
            RTPP_OBJ_DECREF(wi);
            break;
        }
        wip = rtpp_wi_data_get_ptr(wi, sizeof(*wip), sizeof(*wip));
        struct rtpp_dtls_gw_aux *edp = &wip->edata;
        switch (edp->direction) {
        case DTLS_IN:
#if 0
            RTPP_LOG(edp->mself->log, RTPP_LOG_DBUG, "Packet from DTLS");
#endif
            CALL_SMETHOD(edp->dtls_conn, dtls_recv, wip->pktx.pktp);
            res = RES_HERE(1);
            break;
        case SRTP_IN:
#if 0
            RTPP_LOG(RTPP_MOD_SELF.log, RTPP_LOG_DBUG, "DTLS: packet SRTP->RTP");
#endif
            res = CALL_SMETHOD(edp->dtls_conn, srtp_recv, &wip->pktx);
            break;
        case RTP_OUT:
#if 0
            RTPP_LOG(RTPP_MOD_SELF.log, RTPP_LOG_DBUG, "DTLS: packet RTP->SRTP");
#endif
            res = CALL_SMETHOD(edp->dtls_conn, rtp_send, &wip->pktx);
            break;
        default:
            abort();
        }
        if (res.v != 0) {
            switch (edp->direction) {
            case DTLS_IN:
                break;
            case SRTP_IN:
                CALL_SMETHOD(wip->pktx.strmp_in->pcnt_strm, reg_pktin, wip->pktx.pktp);
                /* Fallthrouth */
            case RTP_OUT:
                CALL_SMETHOD(wip->pktx.strmp_in->pcount, reg_drop, res.loc);
                CALL_SMETHOD(wip->pktx.strmp_in->pproc_manager, reg_drop);
                break;
            }
            RTPP_OBJ_DECREF(wip->pktx.pktp);
        }
        RTPP_OBJ_DECREF(wi);
    }
}

static struct dtls_gw_stream_cfg *
dtls_gw_data_ctor(struct rtpp_module_priv *pvt, struct rtpp_stream *dtls_strmp)
{
    struct dtls_gw_stream_cfg *rtps_c;

    rtps_c = mod_rzmalloc(sizeof(*rtps_c), offsetof(struct dtls_gw_stream_cfg, rcnt));
    if (rtps_c == NULL) {
        goto e0;
    }
    rtps_c->dtls_conn = CALL_METHOD(pvt->dtls_ctx, newconn, dtls_strmp);
    if (rtps_c->dtls_conn == NULL) {
        goto e1;
    }
    rtps_c->mself = pvt->mself;
    RC_INCREF(pvt->mself->super_rcnt);
    RTPP_OBJ_DTOR_ATTACH_RC(rtps_c, pvt->mself->super_rcnt);
    RTPP_OBJ_DTOR_ATTACH_RC(rtps_c, rtps_c->dtls_conn->rcnt);
    RTPP_OBJ_DTOR_ATTACH(rtps_c, GET_SMETHOD(rtps_c->dtls_conn, godead),
      rtps_c->dtls_conn);
    rtps_c->mself = pvt->mself;
    return (rtps_c);
e1:
    mod_free(rtps_c);
e0:
    return (NULL);
}

static int
rtpp_dtls_gw_setup_sender(struct rtpp_module_priv *pvt,
  struct rtpp_session *spa, struct rtpp_stream *dtls_strmp)
{
    int sidx, lport;
    struct rtpp_socket *fd, *fds[2];

    fd = CALL_SMETHOD(dtls_strmp, get_skt, HEREVAL);
    if (fd != NULL) {
        RTPP_OBJ_DECREF(fd);
        return (0);
    }

    if (spa->rtp->stream[0] == dtls_strmp) {
        sidx = 0;
    } else if (spa->rtp->stream[1] == dtls_strmp) {
        sidx = 1;
    } else {
        abort();
    }

    if (rtpp_create_listener(pvt->cfsp, dtls_strmp->laddr, &lport, fds) == -1)
        return (-1);
    CALL_SMETHOD(pvt->cfsp->sessinfo, append, spa, sidx, fds);
    CALL_METHOD(pvt->cfsp->rtpp_proc_cf, nudge);
    RTPP_OBJ_DECREF(fds[0]);
    RTPP_OBJ_DECREF(fds[1]);
    dtls_strmp->port = lport;
    spa->rtcp->stream[sidx]->port = lport + 1;
    if (spa->complete == 0) {
        CALL_SMETHOD(pvt->cfsp->rtpp_stats, updatebyname, "nsess_complete", 1);
        CALL_SMETHOD(spa->rtp->stream[0]->ttl, reset_with,
          pvt->cfsp->max_ttl);
        CALL_SMETHOD(spa->rtp->stream[1]->ttl, reset_with,
          pvt->cfsp->max_ttl);
    }
    spa->complete = 1;
    return (0);
}

enum rdg_cmd {RDG_CMD_A, RDG_CMD_P, RDG_CMD_S, RDG_CMD_D, RDG_CMD_U};

static int
rtpp_dtls_gw_handle_command(struct rtpp_module_priv *pvt,
  const struct rtpp_subc_ctx *ctxp)
{
    struct dtls_gw_stream_cfg *rtps_c;
    enum rtpp_dtls_mode my_mode;
    struct rdc_peer_spec rdfs, *rdfsp;
    const rtpp_str_t * argv = rtpp_str_fix(&ctxp->subc_args->v[1]);
    int argc = ctxp->subc_args->c - 1;
    struct rtpp_stream *dtls_strmp;
    int rlen;
    char *rcp;
    enum rdg_cmd rdg_cmd;

    if (argc != 1 && argc != 3 && argc != 4) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "expected 1, 3 or 4 parameters: %d",
          argc);
        return (-1);
    }

    switch (argv[0].s[0] | argv[0].s[1]) {
    case 'a':
    case 'A':
        if (argc != 3 && argc != 4)
            goto invalmode;
        rdfs.peer_mode = RTPP_DTLS_ACTIVE;
        rdg_cmd = RDG_CMD_A;
        break;

    case 'p':
    case 'P':
        if (argc != 3 && argc != 4)
            goto invalmode;
        rdfs.peer_mode = RTPP_DTLS_PASSIVE;
        rdg_cmd = RDG_CMD_P;
        break;

    case 's':
    case 'S':
        if (argc != 1)
            goto invalmode;
        rdg_cmd = RDG_CMD_S;
        break;

    case 'd':
    case 'D':
        if (argc != 1)
            goto invalmode;
        rdg_cmd = RDG_CMD_D;
        break;

    case 'u':
    case 'U':
        if (argc != 1)
            goto invalmode;
        rdg_cmd = RDG_CMD_U;
        break;

    default:
        goto invalmode;
    }

    switch (rdg_cmd) {
    case RDG_CMD_A:
    case RDG_CMD_P:
        if (argv[1].len > sizeof(rdfs.alg_buf))
            goto invalalg;
        for (int i = 0; i < argv[1].len; i++) {
            rdfs.alg_buf[i] = argv[1].s[i];
            if (rdfs.alg_buf[i] >= 'a')
                rdfs.alg_buf[i] -= ('a' - 'A');
        }
        rdfs.algorithm.len = argv[1].len;
        rdfs.algorithm.s = rdfs.alg_buf;
        rdfs.fingerprint = &argv[2];
        rdfs.ssrc = (argc == 4) ? &argv[3] : NULL;
        rdfsp = &rdfs;
        /* Fallthrough */
    case RDG_CMD_D:
        dtls_strmp = ctxp->strmp_in;
        break;

    case RDG_CMD_S:
        rdfsp = NULL;
        /* Fallthrough */
    case RDG_CMD_U:
        dtls_strmp = ctxp->strmp_out;
        break;
    }

    struct packet_processor_if dtls_in_poi;

    int lookup_res = CALL_SMETHOD(dtls_strmp->pproc_manager, lookup, pvt, &dtls_in_poi);
    if (lookup_res != 0) {
        rtps_c = dtls_in_poi.arg;
    }

    if (rdg_cmd == RDG_CMD_D || rdg_cmd == RDG_CMD_U) {
        if (lookup_res == 0) {
            return (-1);
        }
        CALL_SMETHOD(dtls_strmp->pproc_manager, unreg, pvt);
        CALL_SMETHOD(dtls_strmp->pproc_manager->reverse, unreg, pvt + 1);
        goto out;
    }

    if (lookup_res == 0) {
        rtps_c = dtls_gw_data_ctor(pvt, dtls_strmp);
        if (rtps_c == NULL) {
            return (-1);
        }
    }
    if (rdfsp != NULL && rdfs.peer_mode == RTPP_DTLS_PASSIVE) {
        if (rtpp_dtls_gw_setup_sender(pvt, ctxp->sessp, dtls_strmp) != 0) {
            goto e0;
        }
    }
    my_mode = CALL_SMETHOD(rtps_c->dtls_conn, setmode, rdfsp);
    if (my_mode == RTPP_DTLS_MODERR) {
        goto e0;
    }
    if (lookup_res == 0) {
        dtls_in_poi = (struct packet_processor_if){
            .descr = "dtls (srtp->rtp)",
            .taste = rtpp_dtls_gw_taste_encrypted,
            .enqueue = rtpp_dtls_gw_enqueue,
            .key = pvt,
            .arg = rtps_c,
            .rcnt = rtps_c->rcnt
        };
        if (CALL_SMETHOD(dtls_strmp->pproc_manager, reg, PPROC_ORD_DECRYPT, &dtls_in_poi) < 0) {
            goto e0;
        }
        const struct packet_processor_if dtls_out_poi = {
            .descr = "dtls (rtp->srtp)",
            .taste = rtpp_dtls_gw_taste_plain,
            .enqueue = rtpp_dtls_gw_enqueue,
            .key = pvt + 1,
            .arg = rtps_c,
            .rcnt = rtps_c->rcnt
        };
        if (CALL_SMETHOD(dtls_strmp->pproc_manager->reverse, reg, PPROC_ORD_ENCRYPT, &dtls_out_poi) < 0) {
            goto e1;
        }
    }
    if (rdfsp == NULL) {
        rcp = ctxp->resp->buf_t;
        rlen = sizeof(ctxp->resp->buf_t);

        switch (my_mode) {
        case RTPP_DTLS_ACTPASS:
            strlcpy(rcp, "actpass ", rlen);
            rcp += strlen("actpass ");
            rlen -= strlen("actpass ");
            break;

        case RTPP_DTLS_ACTIVE:
            strlcpy(rcp, "active ", rlen);
            rcp += strlen("active ");
            rlen -= strlen("active ");
            break;

        case RTPP_DTLS_PASSIVE:
            strlcpy(rcp, "passive ", rlen);
            rcp += strlen("passive ");
            rlen -= strlen("passive ");
            break;

        default:
            abort();
        }

        strlcpy(rcp, pvt->dtls_ctx->fingerprint, rlen);
    }
out:
    RTPP_OBJ_DECREF(rtps_c);
    return (0);

invalalg:
    RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "invalid algorithm: \"%s\"",
      argv[1].s);
    return (-1);
invalmode:
    RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "invalid mode: \"%s\"",
      argv[0].s);
    return (-1);
e1:
    CALL_SMETHOD(dtls_strmp->pproc_manager, unreg, pvt);
e0:
    RTPP_OBJ_DECREF(rtps_c);
    return (-1);
}

static int
rtpp_dtls_gw_taste_encrypted(struct pkt_proc_ctx *pktxp)
{
    struct dtls_gw_stream_cfg *rtps_c;
    static __thread struct rtpp_dtls_gw_aux dtls_in = {.direction = DTLS_IN};
    static __thread struct rtpp_dtls_gw_aux strp_in = {.direction = SRTP_IN};
    struct rtpp_dtls_gw_aux *rdgap;

    if (!rtpp_is_dtls_tst(pktxp))
        rdgap = &strp_in;
    else
        rdgap = &dtls_in;
    rtps_c = pktxp->pproc->arg;
    rdgap->dtls_conn = rtps_c->dtls_conn;
    rdgap->mself = rtps_c->mself;
    pktxp->auxp = rdgap;
    return (1);
}

static int
rtpp_dtls_gw_taste_plain(struct pkt_proc_ctx *pktxp)
{
    struct dtls_gw_stream_cfg *rtps_c;
    static __thread struct rtpp_dtls_gw_aux rtp_out = {.direction = RTP_OUT};

    if (pktxp->strmp_out == NULL)
        return (0);
    rtps_c = pktxp->pproc->arg;
    rtp_out.dtls_conn = rtps_c->dtls_conn;
    rtp_out.mself = rtps_c->mself;
    pktxp->auxp = &rtp_out;
    return (1);
}

static struct pproc_act
rtpp_dtls_gw_enqueue(const struct pkt_proc_ctx *pktxp)
{
    struct rtpp_dtls_gw_aux *edata;
    struct rtpp_wi *wi;
    struct wipkt *wip;

    edata = (struct rtpp_dtls_gw_aux *)pktxp->auxp;
    wi = rtpp_wi_malloc_udata((void **)&wip, sizeof(struct wipkt));
    if (wi == NULL)
        return (PPROC_ACT_DROP);
    wip->edata = *edata;
    RTPP_OBJ_BORROW(wi, edata->dtls_conn);
    wip->pktx = *pktxp;
    wip->pktx.rsp = NULL;
    RTPP_OBJ_BORROW(wi, pktxp->strmp_in);
    if (pktxp->strmp_out != NULL)
        RTPP_OBJ_BORROW(wi, pktxp->strmp_out);
    if (rtpp_queue_put_item(wi, edata->mself->wthr.mod_q) != 0) {
        RTPP_OBJ_DECREF(wi);
        return (PPROC_ACT_DROP);
    }

    return (PPROC_ACT_TAKE);
}

static struct rtpp_module_priv *
rtpp_dtls_gw_ctor(const struct rtpp_cfg *cfsp, struct rtpp_minfo *mself)
{
    struct rtpp_module_priv *pvt;
    static int srtp_inited = 0;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->dtls_ctx = rtpp_dtls_ctor(cfsp, mself);
    if (pvt->dtls_ctx == NULL) {
        goto e1;
    }
    if (!srtp_inited && srtp_init() != 0) {
        goto e2;
    }
    srtp_inited = 1;
    pvt->cfsp = cfsp;
    pvt->mself = mself;
    return (pvt);
e2:
    RTPP_OBJ_DECREF(pvt->dtls_ctx);
e1:
    mod_free(pvt);
e0:
    return (NULL);
}

static void
rtpp_dtls_gw_dtor(struct rtpp_module_priv *pvt)
{

    srtp_shutdown();
    RTPP_OBJ_DECREF(pvt->dtls_ctx);
    mod_free(pvt);
    return;
}
