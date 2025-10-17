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
#include <assert.h>
#include <stdbool.h>
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
#include "rtpp_network.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_packetops.h"
#include "rtpp_timeout_data.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_util.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_proc_async.h"
#include "rtpp_netio_async.h"
#include "rtpp_netaddr.h"
#include "rtpp_linker_set.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

#include "rtpp_re.h"
#include "re_types.h"
#include "re_fmt.h"
#include "re_sa.h"
#include "re_ice.h"
#include "re_udp.h"
#include "re_mem.h"
#include "re_list.h"
#include "re_tmr.h"
#include "re_mbuf.h"
#include "re_stun.h"
#include "ice/ice.h"

struct rtpp_module_priv {
    struct rtpp_minfo *mself;
};

struct ila_sock {
    struct sa laddr;
    struct rtpp_netaddr *raddr;
    struct sthread_args *sender;
    struct rtpp_stream *strmp_in;
    udp_helper_recv_h *rh;
    void *rh_arg;
};

struct mux_demux_ctx {
    struct rtpp_stream *strmp_in;
    struct rtpp_stream *strmp_out;
    struct pproc_manager *unreg;
};

struct ice_lite_agent_cfg {
    struct rtpp_refcnt *rcnt;
    pthread_mutex_t state_lock;
    struct icem *icem;
    struct ila_sock *sock;
    struct mbuf *mb;
    _Atomic(bool) completed;
    struct mux_demux_ctx rtcp_dmx_ctx;
    struct mux_demux_ctx rtcp_mx_ctx;
    struct rtpp_minfo *mself;
};

static struct rtpp_module_priv *rtpp_ice_lite_ctor(const struct rtpp_cfg *,
  struct rtpp_minfo *);
static void rtpp_ice_lite_dtor(struct rtpp_module_priv *);
static void rtpp_ice_lite_worker(const struct rtpp_wthrdata *);
static int rtpp_ice_lite_handle_command(struct rtpp_module_priv *,
  const struct rtpp_subc_ctx *);
static struct pproc_act rtpp_ice_lite_rtcp_dmx(const struct pkt_proc_ctx *);
static struct pproc_act rtpp_ice_lite_rtcp_mx(const struct pkt_proc_ctx *);
static struct pproc_act rtpp_ice_lite_enqueue(const struct pkt_proc_ctx *);
static int ril_ice_taste(struct pkt_proc_ctx *);

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"
void *_libre_memdeb;
RTPP_MEMDEB_APP_STATIC;
#endif

const struct rtpp_minfo RTPP_MOD_SELF = {
    .descr.name = "ice_lite",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 5,
    .proc.ctor = rtpp_ice_lite_ctor,
    .proc.dtor = rtpp_ice_lite_dtor,
    .wapi = &(const struct rtpp_wthr_handlers){
        .main_thread = rtpp_ice_lite_worker,
        .queue_size = RTPQ_MEDIUM_CB_LEN,
     },
    .capi = &(const struct rtpp_cplane_handlers){.ul_subc_handle = rtpp_ice_lite_handle_command},
    .fn = &(struct rtpp_minfo_fset){0},
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM
#endif
};
#if defined(LIBRTPPROXY)
DATA_SET(rtpp_modules, RTPP_MOD_SELF);
#endif

struct wipkt {
    struct rtp_packet *pkt;
    struct ice_lite_agent_cfg *ila_c;
    struct rtpp_stream *strmp_in;
};

void
re_dbg_printf(int level, const char *buf, int len)
{
#if defined(RTPP_DEBUG)
    fprintf(stderr, "%.*s", len, buf);
#endif
}

int
udp_register_helper(struct udp_helper **uhp, struct udp_sock *us, int layer,
  udp_helper_send_h *sh, udp_helper_recv_h *rh, void *arg)
{
    struct ila_sock *sock = (struct ila_sock *)us;
    assert(sock->rh == NULL && sock->rh_arg == NULL);
    sock->rh = rh;
    sock->rh_arg = arg;
    return (0);
}

static void
rtpp2re_sa(struct sa *sad, const struct sockaddr *sas)
{

    memcpy(&sad->u.sa, sas, SA_LEN(sas));
    sad->len = SA_LEN(sas);
}

int
udp_send(struct udp_sock *us, const struct sa *dst, struct mbuf *mb)
{
    struct ila_sock *sock = (struct ila_sock *)us;
    struct rtp_packet *packet;

    packet = rtp_packet_alloc();
    if (packet == NULL)
        return (ENOMEM);
    memcpy(packet->data.buf, mb->buf, mb->end);
    packet->size = mb->end;
    CALL_SMETHOD(sock->raddr, set, &dst->u.sa, dst->len);
    CALL_SMETHOD(sock->strmp_in, send_pkt_to, sock->sender, packet, sock->raddr);
    return (0);
}

static bool
iscompleted(const struct icem *icem)
{
    struct le *le;
    bool rval = false;

    for (le = icem->validl.head; le; le = le->next) {
        const struct ice_candpair *cp = le->data;
        if (!icem_candpair_iscompleted(cp))
            return false;
        rval = true;
    }

    return rval;
}

static bool
ila_iscompleted(struct ice_lite_agent_cfg *ila_c)
{
    return atomic_load_explicit(&ila_c->completed, memory_order_relaxed);
}

static void
rtpp_ice_lite_worker(const struct rtpp_wthrdata *wp)
{
    struct rtpp_wi *wi;
    struct wipkt *wip;
    struct rtp_packet *pkt;
    struct mbuf *mb;
    struct ice_lite_agent_cfg *ila_c;

    for (;;) {
        wi = rtpp_queue_get_item(wp->mod_q, 0);
        if (wi == wp->sigterm) {
            RTPP_OBJ_DECREF(wi);
            break;
        }
        wip = rtpp_wi_data_get_ptr(wi, sizeof(*wip), sizeof(*wip));
        pkt = wip->pkt;
        ila_c = wip->ila_c;
        pthread_mutex_lock(&ila_c->state_lock);
        mb = ila_c->mb;
        assert(pkt->size <= mb->size);
        memcpy(mb->buf, pkt->data.buf, pkt->size);
        mb->end = pkt->size;
        struct sa raddr = {0};
        rtpp2re_sa(&raddr, sstosa(&pkt->raddr));
        ila_c->sock->strmp_in = wip->strmp_in;
        ila_c->sock->rh(&raddr, mb, ila_c->sock->rh_arg);
        bool completed = iscompleted(ila_c->icem);
        if (!ila_iscompleted(ila_c) && completed) {
            RTPP_LOG(ila_c->sock->strmp_in->log, RTPP_LOG_INFO, "ICE completed");
            CALL_SMETHOD(ila_c->sock->strmp_in, latch_setmode, RTPLM_FORCE_ON);
            CALL_SMETHOD(ila_c->sock->strmp_in, latch, pkt);
            atomic_store_explicit(&ila_c->completed, true, memory_order_relaxed);
        }
        pthread_mutex_unlock(&ila_c->state_lock);
        RTPP_OBJ_DECREF(pkt);
        RTPP_OBJ_DECREF(wi);
    }
}

static void
ice_lite_data_dtor(struct ice_lite_agent_cfg *pvt)
{

    pthread_mutex_destroy(&pvt->state_lock);
    RTPP_OBJ_DECREF(pvt->sock->raddr);
    mem_deref(pvt->mb->buf);
    mem_deref(pvt->mb);
    mem_deref(pvt->sock);
    mem_deref(pvt->icem);
    RC_DECREF(pvt->mself->super_rcnt);
}

int
udp_local_get(const struct udp_sock *us, struct sa *local)
{
    struct ila_sock *sock = (struct ila_sock *)us;
    *local = sock->laddr;
    return (0);
}

static struct ice_lite_agent_cfg *
ice_lite_data_ctor(int lufrag_len, int lpwd_len, struct rtpp_minfo *mself)
{
    struct ice_lite_agent_cfg *ila_c;
    rtpp_str_mutble_t lufrag, lpwd;
    uint64_t tiebrk = 1;

    ila_c = mod_rzmalloc(sizeof(*ila_c), offsetof(typeof(*ila_c), rcnt));
    if (ila_c == NULL)
        goto e0;
    atomic_init(&ila_c->completed, false);
    lufrag.s = alloca(lufrag_len + 1);
    lpwd.s = alloca(lpwd_len + 1);
    if (lufrag.s == NULL || lpwd.s == NULL)
        goto e1;
    lufrag.len = lufrag_len;
    generate_random_string(lufrag.s, lufrag.len);
    lpwd.len = lpwd_len;
    generate_random_string(lpwd.s, lpwd.len);
    if (icem_alloc(&ila_c->icem, ICE_MODE_LITE, ICE_ROLE_CONTROLLED, IPPROTO_UDP, 0,
      tiebrk, lufrag.s, lpwd.s, NULL, NULL) != 0)
        goto e1;
    ila_c->sock = mem_zalloc(sizeof(*ila_c->sock), NULL);
    if (ila_c->sock == NULL)
        goto e2;
    ila_c->mb = mem_zalloc(sizeof(*ila_c->mb), NULL);
    if (ila_c->mb == NULL)
        goto e3;
    ila_c->mb->buf = mem_zalloc(MAX_RPKT_LEN, NULL);
    if (ila_c->mb->buf == NULL)
        goto e4;
    ila_c->mb->size = MAX_RPKT_LEN;
    ila_c->sock->raddr = rtpp_netaddr_ctor();
    if (ila_c->sock->raddr == NULL)
        goto e5;
    if (pthread_mutex_init(&ila_c->state_lock, NULL) != 0)
        goto e6;
    RC_INCREF(mself->super_rcnt);
    ila_c->mself = mself;
    CALL_SMETHOD(ila_c->rcnt, attach, (rtpp_refcnt_dtor_t)ice_lite_data_dtor, ila_c);
    return (ila_c);
e6:
    RTPP_OBJ_DECREF(ila_c->sock->raddr);
e5:
    mem_deref(ila_c->mb->buf);
e4:
    mem_deref(ila_c->mb);
e3:
    mem_deref(ila_c->sock);
e2:
    mem_deref(ila_c->icem);
e1:
    mod_free(ila_c);
e0:
    return (NULL);
}

static int
ila_set_rauth(struct ice_lite_agent_cfg *ila_c, const rtpp_str_t *ice_rufrag,
  const rtpp_str_t *ice_rpwd)
{

    pthread_mutex_lock(&ila_c->state_lock);
    if (icem_sdp_decode(ila_c->icem, "ice-ufrag", ice_rufrag->s) != 0)
        goto e0;
    if (icem_sdp_decode(ila_c->icem, "ice-pwd", ice_rpwd->s) != 0)
        goto e0;
    pthread_mutex_unlock(&ila_c->state_lock);
    return 0;
e0:
    pthread_mutex_unlock(&ila_c->state_lock);
    return -1;
}

enum ril_cmd {RIL_CMD_A, RIL_CMD_C, RIL_CMD_S, RIL_CMD_D, RIL_CMD_U};
#define ICE_COMPID_RTP  1
#define ICE_COMPID_RTCP 2

#define ICE_LUFRAG_LEN 4
#define ICE_LPWD_LEN 24

static int
ice_lite_candidate(struct ice_lite_agent_cfg *ila_c, int c, const rtpp_str_t *v)
{
    struct rtpp_command_argsp args = {.c = c, .v = v};
    pthread_mutex_lock(&ila_c->state_lock);
    int err = rtpp_cand_decode(ila_c->icem, &args, ila_c->mself->log);
    pthread_mutex_unlock(&ila_c->state_lock);
    return (err);
}

static int
cand_printf_handler(const char *p, size_t size, void *arg)
{
    rtpp_str_mutble_t *resp = (rtpp_str_mutble_t *)arg;
    if (size + 1 > resp->len)
        return (ENOMEM);
    int len = url_quote(p, resp->s, size, resp->len);
    if (len < 0)
        return (ENOMEM);
    resp->s += len;
    resp->len -= len;
    return (0);
}

#define APPEND(bs, ss) ({size_t len = strlcpy(bs->s, ss, bs->len); \
  int err = (len > bs->len); bs->len -= (err) ? 0:len, bs->s += (err) ? 0:len; err;})

static int
ice_lite_start(struct ice_lite_agent_cfg *ila_c, struct rtpp_stream *isp,
  rtpp_str_mutble_t *resp)
{
    int err;
    struct sa *laddr;

    pthread_mutex_lock(&ila_c->state_lock);
    laddr = &ila_c->sock->laddr;
    if (laddr->len == 0) {
        const struct sockaddr *s_laddr = isp->laddr;
        memcpy(&laddr->u.sa, s_laddr, SA_LEN(s_laddr));
        laddr->len = SA_LEN(s_laddr);
        sa_set_port(laddr, isp->port);

        err = icem_comp_add(ila_c->icem, ICE_COMPID_RTP, ila_c->sock);
        if (err != 0)
            goto e0;
        err = icem_cand_add(ila_c->icem, ICE_COMPID_RTP, 0, NULL, laddr);
        if (err != 0)
            goto e0;
    }
    if (APPEND(resp, ila_c->icem->lufrag) < 0)
        goto e0;
    if (APPEND(resp, " ") < 0)
        goto e0;
    if (APPEND(resp, ila_c->icem->lpwd) < 0)
        goto e0;
    struct re_printf pt = {.vph = cand_printf_handler, .arg = resp};
    struct list *canlist = icem_lcandl(ila_c->icem);
    for(struct le *le = canlist->head; le; le = le->next) {
        if (APPEND(resp, " c:") < 0)
            goto e0;
        err = ice_cand_encode(&pt, (struct ice_cand *)le->data);
        if (err  != 0)
            goto e0;
    }
    pthread_mutex_unlock(&ila_c->state_lock);
    return (0);
e0:
    pthread_mutex_unlock(&ila_c->state_lock);
    return (-1);
}

static struct ice_lite_agent_cfg *
ice_lite_activate(struct rtpp_module_priv *pvt, const struct rtpp_subc_ctx *ctxp,
  struct rtpp_stream *ice_strmp, int lufrag_len, int lpwd_len)
{
    struct ice_lite_agent_cfg *ila_c;
    struct packet_processor_if stun_poi;

    ila_c = ice_lite_data_ctor(lufrag_len, lpwd_len, pvt->mself);
    if (ila_c == NULL) {
        goto e0;
    }
    stun_poi = (struct packet_processor_if) {
        .descr = "stun/ice",
        .taste = ril_ice_taste,
        .enqueue = rtpp_ice_lite_enqueue,
        .key = pvt,
        .arg = ila_c,
        .rcnt = ila_c->rcnt
    };
    if (CALL_SMETHOD(ice_strmp->pproc_manager, reg, PPROC_ORD_RECV,
      &stun_poi) < 0)
        goto e1;
    struct rtpp_stream_pair rtcp = get_rtcp_pair(ctxp->sessp, ice_strmp);
    if (rtcp.ret != 0) {
        goto e2;
    }
    if (rtcp.in != NULL) {
        struct packet_processor_if rtcp_dmx_poi = {
            .descr = "rtcp demux",
            .taste = rtpp_is_rtcp_tst,
            .enqueue = rtpp_ice_lite_rtcp_dmx,
            .key = pvt + 1,
            .arg = &ila_c->rtcp_dmx_ctx,
            .rcnt = ila_c->rcnt
        };
        ila_c->rtcp_dmx_ctx = (struct mux_demux_ctx) {
            .strmp_in = rtcp.in,
            .strmp_out = rtcp.out,
        };
        if (CALL_SMETHOD(ice_strmp->pproc_manager, reg, PPROC_ORD_CT_RECV,
            &rtcp_dmx_poi) < 0)
            goto e2;
        struct packet_processor_if rtcp_mx_poi = {
            .descr = "rtcp mux",
            .taste = rtpp_is_rtcp_tst,
            .enqueue = rtpp_ice_lite_rtcp_mx,
            .key = pvt + 2,
            .arg = &ila_c->rtcp_mx_ctx,
            .rcnt = ila_c->rcnt
        };
        ila_c->rtcp_mx_ctx = (struct mux_demux_ctx) {
            .strmp_in = rtcp.out,
            .strmp_out = ice_strmp,
            .unreg = rtcp.in->pproc_manager->reverse,
        };
        if (CALL_SMETHOD(rtcp.in->pproc_manager->reverse, reg, PPROC_ORD_CT_SEND,
            &rtcp_mx_poi) < 0)
            goto e3;
    }
    CALL_SMETHOD(ice_strmp, latch_setmode, RTPLM_FORCE_OFF);
    return (ila_c);
e3:
    CALL_SMETHOD(ice_strmp->pproc_manager, unreg, pvt + 1);
e2:
    CALL_SMETHOD(ice_strmp->pproc_manager, unreg, pvt);
e1:
    RTPP_OBJ_DECREF(ila_c);
e0:
    return (NULL);
}

static int
rtpp_ice_lite_handle_command(struct rtpp_module_priv *pvt,
  const struct rtpp_subc_ctx *ctxp)
{
    struct ice_lite_agent_cfg *ila_c;
    const rtpp_str_t *rufrag, *rpwd;
    enum ril_cmd ril_cmd;
    const rtpp_str_t *argv = rtpp_str_fix(&ctxp->subc_args->v[1]);
    int argc = ctxp->subc_args->c - 1;
    struct rtpp_stream *ice_strmp;

    if (argc < 1) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR,
          "expected at least 1 parameter: %d", argc);
        return (-1);
    }
    {static int b=0; while (b);}

    switch (argv[0].s[0] | argv[0].s[1]) {
    case 'a':
    case 'A':
        if (argc != 3)
            goto invalmode;
        ril_cmd = RIL_CMD_A;
        break;

    case 'c':
    case 'C':
        if (argc < 9)
            goto invalmode;
        ril_cmd = RIL_CMD_C;
        break;

    case 's':
    case 'S':
        if (argc != 1)
            goto invalmode;
        ril_cmd = RIL_CMD_S;
        break;

    case 'd':
    case 'D':
        if (argc != 1)
            goto invalmode;
        ril_cmd = RIL_CMD_D;
        break;

    case 'u':
    case 'U':
        if (argc != 1)
            goto invalmode;
        ril_cmd = RIL_CMD_U;
        break;

    default:
        goto invalmode;
    }

    switch (ril_cmd) {
    case RIL_CMD_A:
        rufrag = rtpp_str_fix(&argv[1]);
        rpwd = rtpp_str_fix(&argv[2]);
    case RIL_CMD_C:
    case RIL_CMD_D:
        ice_strmp = ctxp->strmp_in;
        break;

    case RIL_CMD_S:
    case RIL_CMD_U:
        ice_strmp = ctxp->strmp_out;
        break;
    }

    struct packet_processor_if stun_poi;

    int lookup_res = CALL_SMETHOD(ice_strmp->pproc_manager, lookup, pvt, &stun_poi);

    if (lookup_res != 0) {
        ila_c = stun_poi.arg;
    }

    switch (ril_cmd) {
    case RIL_CMD_D:
    case RIL_CMD_U:
        if (lookup_res == 0)
            return (-1);
        RTPP_OBJ_INCREF(ila_c); /* for the unlock */
        pthread_mutex_lock(&ila_c->state_lock);
        CALL_SMETHOD(ila_c->rtcp_mx_ctx.unreg, unreg, pvt + 2);
        CALL_SMETHOD(ice_strmp->pproc_manager, unreg, pvt + 1);
        CALL_SMETHOD(ice_strmp->pproc_manager, unreg, pvt);
        CALL_SMETHOD(ice_strmp, latch_setmode, RTPLM_NORMAL);
        pthread_mutex_unlock(&ila_c->state_lock);
        RTPP_OBJ_DECREF(ila_c);
        break;

    case RIL_CMD_C:
        if (lookup_res == 0)
            return (-1);
        if (ice_lite_candidate(ila_c, argc - 1, argv + 1) != 0)
            goto e0;
        break;

   case RIL_CMD_S:
        if (lookup_res == 0) {
            ila_c = ice_lite_activate(pvt, ctxp, ice_strmp, ICE_LUFRAG_LEN, ICE_LPWD_LEN);
            if (ila_c == NULL)
               return (-1);
        }
        rtpp_str_mutble_t resp = {.s = ctxp->resp->buf_t, .len = sizeof(ctxp->resp->buf_t)};
        if (ice_lite_start(ila_c, ice_strmp, &resp) != 0) {
            goto e0;
        }
        break;

    case RIL_CMD_A:
        if (lookup_res == 0) {
            ila_c = ice_lite_activate(pvt, ctxp, ice_strmp, rufrag->len, rpwd->len);
            if (ila_c == NULL)
                return (-1);
        }
        if (ila_set_rauth(ila_c, rufrag, rpwd) != 0)
            goto e0;
        break;
   }

    RTPP_OBJ_DECREF(ila_c);
    return (0);

invalmode:
    RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "invalid mode: \"%s\"",
      argv[0].s);
    return (-1);
e0:
    RTPP_OBJ_DECREF(ila_c);
    return (-1);
}

static int
ril_ice_taste(struct pkt_proc_ctx *pktx)
{
    struct ice_lite_agent_cfg *ila_c;

    ila_c = pktx->pproc->arg;
    if (!rtpp_is_stun_tst(pktx)) {
        if (!ila_iscompleted(ila_c)) {
            pktx->auxp = NULL;
            return (true);
        }
        return (false);
    }
    pktx->auxp = ila_c;
    return (true);
}

static struct pproc_act
rtpp_ice_lite_enqueue(const struct pkt_proc_ctx *pktx)
{
    struct rtpp_wi *wi;
    struct wipkt *wip;
    struct ice_lite_agent_cfg *ila_c;

    ila_c = (struct ice_lite_agent_cfg *)pktx->auxp;
    if (ila_c == NULL)
        return (PPROC_ACT_DROP);
    wi = rtpp_wi_malloc_udata((void **)&wip, sizeof(struct wipkt));
    if (wi == NULL)
        return (PPROC_ACT_DROP);
    wip->pkt = pktx->pktp;
    RTPP_OBJ_BORROW(wi, ila_c);
    wip->ila_c = ila_c;
    RTPP_OBJ_BORROW(wi, pktx->strmp_in);
    wip->strmp_in = pktx->strmp_in;
    if (rtpp_queue_put_item(wi, ila_c->mself->wthr.mod_q) != 0) {
        RTPP_OBJ_DECREF(wi);
        return (PPROC_ACT_DROP);
    }
    return (PPROC_ACT_TAKE);
}

static struct pproc_act
rtpp_ice_lite_rtcp_dmx(const struct pkt_proc_ctx *pktx)
{
    struct mux_demux_ctx *ctx = pktx->pproc->arg;
    struct pkt_proc_ctx opktx = {.strmp_in = ctx->strmp_in, .strmp_out = ctx->strmp_out,
      .pktp = pktx->pktp, .flags = pktx->flags};
    return CALL_SMETHOD(opktx.strmp_in->pproc_manager, handleat, &opktx, PPROC_ORD_CT_RECV);
}

static struct pproc_act
rtpp_ice_lite_rtcp_mx(const struct pkt_proc_ctx *pktx)
{
    struct mux_demux_ctx *ctx = pktx->pproc->arg;
    struct pkt_proc_ctx opktx = {.strmp_in = ctx->strmp_in, .strmp_out = ctx->strmp_out,
      .pktp = pktx->pktp, .flags = pktx->flags};
    return CALL_SMETHOD(opktx.strmp_out->pproc_manager->reverse, handleat, &opktx, PPROC_ORD_CT_SEND);
}

static struct rtpp_module_priv *
rtpp_ice_lite_ctor(const struct rtpp_cfg *cfsp, struct rtpp_minfo *mself)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
#ifdef RTPP_CHECK_LEAKS
    _libre_memdeb = *mself->memdeb_p;
#endif
    pvt->mself = mself;
    return (pvt);

e0:
    return (NULL);
}

static void
rtpp_ice_lite_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}
