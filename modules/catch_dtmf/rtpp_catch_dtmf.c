#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rtpp_log.h"
#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_wi.h"
#include "rtpp_wi_sgnl.h"
#include "rtpp_wi_data.h"
#include "rtpp_queue.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_log_obj.h"

#include "advanced/packet_observer.h"
#include "advanced/po_manager.h"
#include "../modules/catch_dtmf/rtpp_catch_dtmf.h"

struct rtpp_catch_dtmf_pvt {
    struct rtpp_catch_dtmf pub;
    struct rtpp_wi *sigterm;
    struct rtpp_queue *q;
    pthread_t worker;
    struct rtpp_log *log;
};

struct catch_dtmf_stream_cfg {
    atomic_int pt;
};

#define PUB2PVT(pubp, pvtp) \
    (pvtp) = (typeof(pvtp))((char *)(pubp) - offsetof(typeof(*(pvtp)), pub))

static void
rtpp_catch_dtmf_dtor(struct rtpp_catch_dtmf_pvt *pvt)
{

    rtpp_queue_put_item(pvt->sigterm, pvt->q);
    pthread_join(pvt->worker, NULL);
    rtpp_queue_destroy(pvt->q);
    CALL_METHOD(pvt->sigterm, dtor);
    CALL_SMETHOD(pvt->log->rcnt, decref);
    free(pvt);
}

struct wipkt {
    const struct rtp_packet *pkt;
};

static void
rtpp_catch_dtmf_worker(void *arg)
{
    struct rtpp_catch_dtmf_pvt *pvt;
    struct rtpp_wi *wi;
    struct wipkt *wip;

    pvt = (struct rtpp_catch_dtmf_pvt *)arg;
    for (;;) {
        wi = rtpp_queue_get_item(pvt->q, 0);
        if (wi == pvt->sigterm) {
            break;
        }
        wip = rtpp_wi_data_get_ptr(wi, sizeof(*wip), sizeof(*wip));
        RTPP_LOG(pvt->log, RTPP_LOG_ERR, "rtpp_catch_dtmf_worker(%p)", wip->pkt);
        CALL_SMETHOD(wip->pkt->rcnt, decref);
        CALL_METHOD(wi, dtor);
    }
}

static int
rtpp_catch_dtmf_handle_command(struct rtpp_catch_dtmf *pub,
  struct rtpp_stream *rsp, const struct rtpp_command_args *subc_args)
{
    struct rtpp_catch_dtmf_pvt *pvt;
    struct catch_dtmf_stream_cfg *rtps_c;
    void *rtps_c_prev;
    int new_pt = 101;
    int old_pt = -1;

    rtps_c_prev = NULL;

    rtps_c = atomic_load(&(rsp->catch_dtmf_data));
    if (rtps_c == NULL) {
        rtps_c = rtpp_zmalloc(sizeof(*rtps_c));
        if (rtps_c == NULL) {
            return (-1);
        }
        atomic_init(&(rtps_c->pt), new_pt);
        if (!atomic_compare_exchange_strong(&(rsp->catch_dtmf_data),
          &rtps_c_prev, rtps_c)) {
            free(rtps_c);
            rtps_c = (typeof(rtps_c))rtps_c_prev;
            old_pt = atomic_exchange(&(rtps_c->pt), new_pt);
        }
    }
    PUB2PVT(pub, pvt);
    RTPP_LOG(pvt->log, RTPP_LOG_ERR, "rtpp_catch_dtmf_handle_command(%p), pt=%d->%d",
      rsp, old_pt, new_pt);
    return (0);
}

static int
rtp_packet_is_dtmf(struct rtpp_stream *rtps, const struct rtp_packet *pkt)
{
    struct catch_dtmf_stream_cfg *rtps_c;

    if (rtps->pipe_type != PIPE_RTP)
        return (0);
    rtps_c = atomic_load(&(rtps->catch_dtmf_data));
    if (rtps_c == NULL)
        return (0);
    if (atomic_load(&(rtps_c->pt)) != pkt->data.header.pt)
        return (0);

    return (1);
}

static void
rtpp_catch_dtmf_enqueue(void *arg, const struct rtpp_session *sp,
  const struct rtpp_stream *rsp, const struct rtp_packet *pkt)
{
    struct rtpp_catch_dtmf_pvt *pvt;
    struct rtpp_wi *wi;
    struct wipkt *wip;

    pvt = (struct rtpp_catch_dtmf_pvt *)arg;
    wi = rtpp_wi_malloc_udata((void **)&wip, sizeof(struct wipkt));
    if (wi == NULL)
        return;
    CALL_SMETHOD(pkt->rcnt, incref);
    wip->pkt = pkt;
    rtpp_queue_put_item(wi, pvt->q);
}

struct rtpp_catch_dtmf *
rtpp_catch_dtmf_ctor(struct rtpp_log *log, struct po_manager *pomp)
{
    struct rtpp_catch_dtmf_pvt *pvt;
    struct rtpp_refcnt *rcnt;
    struct packet_observer_if dtmf_poi;

    pvt = rtpp_rzmalloc(sizeof(*pvt), &rcnt);
    if (pvt == NULL)
        goto e0;
    pvt->pub.rcnt = rcnt;
    pvt->pub.handle_command = rtpp_catch_dtmf_handle_command;
    pvt->sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (pvt->sigterm == NULL)
        goto e1;
    pvt->q = rtpp_queue_init(1, "rtpp_catch_dtmf(%p)", pvt);
    if (pvt->q == NULL)
        goto e2;
    /*
     * Assign log here so it's usable by the worker, but incref later so that
     * we don't have to worry about cleaning it out on error.
     */
    pvt->log = log;
    if (pthread_create(&pvt->worker, NULL, (void *(*)(void *))rtpp_catch_dtmf_worker, pvt) != 0)
        goto e3;
    memset(&dtmf_poi, '\0', sizeof(dtmf_poi));
    dtmf_poi.taste = rtp_packet_is_dtmf;
    dtmf_poi.enqueue = rtpp_catch_dtmf_enqueue;
    dtmf_poi.arg = pvt;
    if (CALL_METHOD(pomp, reg, &dtmf_poi) < 0)
        goto e4;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_catch_dtmf_dtor,
      pvt);
    CALL_SMETHOD(pvt->log->rcnt, incref);
    return (&(pvt->pub));
e4:
    rtpp_queue_put_item(pvt->sigterm, pvt->q);
    pthread_join(pvt->worker, NULL);
e3:
    rtpp_queue_destroy(pvt->q);
e2:
    CALL_METHOD(pvt->sigterm, dtor);
e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}
