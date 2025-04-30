/*
 * Copyright (c) 2006-2020 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#include <sys/socket.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_log.h"
#include "rtpp_mallocs.h"
#include "rtpp_list.h"
#include "rtpp_log_obj.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_acct_rtcp.h"
#include "rtpp_pcount.h"
#include "rtpp_time.h"
#include "rtpp_pcnts_strm.h"
#include "rtpp_codeptr.h"
#include "rtpp_stream.h"
#include "rtpp_pipe.h"
#include "rtpp_session.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"
#define MODULE_IF_CODE
#include "rtpp_module.h"
#include "rtpp_module_acct.h"
#include "rtpp_module_wthr.h"
#include "rtpp_module_cplane.h"
#include "rtpp_module_if.h"
#include "rtpp_modman.h"
#include "rtpp_module_if_fin.h"
#include "rtpp_queue.h"
#include "rtpp_refcnt.h"
#include "rtpp_wi.h"
#include "rtpp_wi_apis.h"
#include "rtpp_wi_sgnl.h"
#include "rtpp_weakref.h"
#include "rtpp_command_sub.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_private.h"
#include "rtpp_refproxy.h"
#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"
#endif
#if defined(LIBRTPPROXY)
#include "rtpp_module_if_static.h"
#endif

struct rtpp_module_if_priv {
    struct rtpp_module_if pub;
    void *dmp;
    struct rtpp_minfo *mip;
    struct rtpp_module_priv *mpvt;
    struct rtpp_log *log;
    struct rtpp_modids ids;
    struct rtpp_weakref *sessions_wrt;
    /* Privary version of the module's memdeb_p, store it here */
    /* just in case module screws it up                        */
    void *memdeb_p;
    int started;
    char mpath[0];
};

static void rtpp_mif_dtor(struct rtpp_module_if_priv *);
static void rtpp_mif_run_acct(void *);
static int rtpp_mif_load(struct rtpp_module_if *, const struct rtpp_cfg *, struct rtpp_log *);
static int rtpp_mif_start(struct rtpp_module_if *, const struct rtpp_cfg *);
static void rtpp_mif_do_acct(struct rtpp_module_if *, struct rtpp_acct *);
static void rtpp_mif_do_acct_rtcp(struct rtpp_module_if *, struct rtpp_acct_rtcp *);
static int rtpp_mif_get_mconf(struct rtpp_module_if *, struct rtpp_module_conf **);
static int rtpp_mif_ul_subc_handle(const struct after_success_h_args *,
  const struct rtpp_subc_ctx *);
static int rtpp_mif_construct(struct rtpp_module_if *self, const struct rtpp_cfg *);
static void rtpp_mif_kaput(struct rtpp_module_if *self);

static const char *do_acct_aname = "do_acct";
static const char *do_acct_rtcp_aname = "do_acct_rtcp";

extern void rtpp_sbuf_ctor(void);
extern void rtpp_sbuf_dtor(void);
extern void rtpp_sbuf_extend(void);
extern void rtpp_sbuf_reset(void);
extern void rtpp_sbuf_write(void);

static const struct rtpp_minfo_fset mip_model = {
#if RTPP_CHECK_LEAKS
    ._malloc = &rtpp_memdeb_malloc,
    ._zmalloc = &rtpp_zmalloc_memdeb,
    ._rzmalloc = &rtpp_rzmalloc_memdeb,
    ._free = &rtpp_memdeb_free,
    ._realloc = &rtpp_memdeb_realloc,
    ._strdup = &rtpp_memdeb_strdup,
    ._asprintf = &rtpp_memdeb_asprintf,
    ._vasprintf = &rtpp_memdeb_vasprintf,
#else
    ._malloc = &malloc,
    ._zmalloc = &rtpp_zmalloc,
    ._rzmalloc = &rtpp_rzmalloc,
    ._free = &free,
    ._realloc = &realloc,
    ._strdup = &strdup,
    ._asprintf = &asprintf,
    ._vasprintf = &vasprintf,
    .auxp = {rtpp_sbuf_ctor, rtpp_sbuf_dtor, rtpp_sbuf_extend,
             rtpp_sbuf_reset, rtpp_sbuf_write, rtpp_refproxy_ctor},
#endif
};

struct rtpp_module_if *
rtpp_module_if_ctor(const char *mpath)
{
    struct rtpp_module_if_priv *pvt;
    size_t msize = sizeof(struct rtpp_module_if_priv);
    int plen = strlen(mpath) + 1;

    msize += plen;
    pvt = rtpp_rzmalloc(msize, PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    memcpy(pvt->mpath, mpath, plen);
    pvt->pub.load = &rtpp_mif_load;
    pvt->pub.construct = &rtpp_mif_construct;
    pvt->pub.do_acct = &rtpp_mif_do_acct;
    pvt->pub.do_acct_rtcp = &rtpp_mif_do_acct_rtcp;
    pvt->pub.start = &rtpp_mif_start;
    pvt->pub.get_mconf = &rtpp_mif_get_mconf;
    pvt->pub.ul_subc_handle = &rtpp_mif_ul_subc_handle;
    pvt->pub.kaput = &rtpp_mif_kaput;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_mif_dtor,
      pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static int
packet_is_rtcp(struct pkt_proc_ctx *pktx)
{

    if (pktx->strmp_in->pipe_type != PIPE_RTCP)
        return (0);
    return (1);
}

static struct pproc_act
acct_rtcp_enqueue(const struct pkt_proc_ctx *pktx)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_acct_rtcp *rarp;
    const struct rtpp_session *sessp;

    pvt = (struct rtpp_module_if_priv *)pktx->pproc->arg;
    sessp = CALL_SMETHOD(pvt->sessions_wrt, get_by_idx, pktx->strmp_in->seuid);
    if (sessp == NULL)
       return (PPROC_ACT_DROP);
    rarp = rtpp_acct_rtcp_ctor(sessp->call_id->s, pktx->pktp);
    RTPP_OBJ_DECREF(sessp);
    if (rarp == NULL) {
        return (PPROC_ACT_DROP);
    }
    rtpp_mif_do_acct_rtcp(&(pvt->pub), rarp);
    return (PPROC_ACT_TEE);
}

static int
rtpp_mif_load(struct rtpp_module_if *self, const struct rtpp_cfg *cfsp, struct rtpp_log *log)
{
    struct rtpp_module_if_priv *pvt;
    const char *derr;
    struct rtpp_minfo *mip = NULL;

    PUB2PVT(self, pvt);
#if defined(LIBRTPPROXY)
    mip = rtpp_static_modules_lookup(pvt->mpath);
    if (mip == NULL)
        goto e1;
#endif
    if (mip == NULL) {
        pvt->dmp = dlopen(pvt->mpath, RTLD_NOW);
        if (pvt->dmp == NULL) {
            derr = dlerror();
            if (strstr(derr, pvt->mpath) == NULL) {
                RTPP_LOG(log, RTPP_LOG_ERR, "can't dlopen(%s): %s", pvt->mpath, derr);
            } else {
                RTPP_LOG(log, RTPP_LOG_ERR, "can't dlopen() module: %s", derr);
            }
            goto e1;
        }
        mip = dlsym(pvt->dmp, "rtpp_module");
        if (mip == NULL) {
            derr = dlerror();
            if (strstr(derr, pvt->mpath) == NULL) {
                RTPP_LOG(log, RTPP_LOG_ERR, "can't find 'rtpp_module' symbol in the %s"
                  ": %s", pvt->mpath, derr);
            } else {
                RTPP_LOG(log, RTPP_LOG_ERR, "can't find 'rtpp_module' symbol: %s",
                  derr);
            }
            goto e2;
        }
    }
    pvt->mip = mip;
    if (!MI_VER_CHCK(pvt->mip)) {
        RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
          "consider recompiling the module", pvt->mpath);
        goto e2;
    }

    pvt->mip->fn = &mip_model;
#if RTPP_CHECK_LEAKS
    if (pvt->mip->memdeb_p == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "memdeb pointer is NULL in the %s, "
          "trying to load non-debug module?", pvt->mpath);
        goto e2;
    }
    pvt->memdeb_p = rtpp_memdeb_init(false);
    if (pvt->memdeb_p == NULL) {
        goto e2;
    }
    rtpp_memdeb_setlog(pvt->memdeb_p, log);
    rtpp_memdeb_setname(pvt->memdeb_p, pvt->mip->descr.name);
    /* We make a copy, so that the module cannot screw us up */
    *pvt->mip->memdeb_p = pvt->memdeb_p;
#else
    if (pvt->mip->memdeb_p != NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "memdeb pointer is not NULL in the %s, "
          "trying to load debug module?", pvt->mpath);
        goto e2;
    }
#endif
    pvt->mip->wthr.sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (pvt->mip->wthr.sigterm == NULL) {
        goto e3;
    }
    int qsize = RTPQ_SMALL_CB_LEN;
    if (pvt->mip->wapi != NULL && pvt->mip->wapi->queue_size > 0)
        qsize = pvt->mip->wapi->queue_size;
    pvt->mip->wthr.mod_q = rtpp_queue_init(qsize, "rtpp_module_if(%s)",
      pvt->mip->descr.name);
    if (pvt->mip->wthr.mod_q == NULL) {
        goto e4;
    }
    rtpp_queue_setmaxlen(pvt->mip->wthr.mod_q, RTPQ_SMALL_CB_LEN * 8);
    RTPP_OBJ_INCREF(log);
    pvt->mip->log = log;
    if (pvt->mip->aapi != NULL) {
        if (pvt->mip->aapi->on_session_end.func != NULL &&
          pvt->mip->aapi->on_session_end.argsize != rtpp_acct_OSIZE()) {
            RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
              "consider recompiling the module", pvt->mpath);
            goto e5;
        }
        if (pvt->mip->aapi->on_rtcp_rcvd.func != NULL &&
          pvt->mip->aapi->on_rtcp_rcvd.argsize != rtpp_acct_rtcp_OSIZE()) {
            RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
              "consider recompiling the module", pvt->mpath);
            goto e5;
        }
        self->has.do_acct = (pvt->mip->aapi->on_session_end.func != NULL);
    }
    self->has.ul_subc_h = (pvt->mip->capi != NULL &&
      pvt->mip->capi->ul_subc_handle != NULL);
    pvt->ids.instance_id = CALL_METHOD(cfsp->modules_cf, get_next_id,
      pvt->mip->descr.module_id);
    pvt->mip->ids = self->ids = &pvt->ids;
    pvt->mip->module_rcnt = self->rcnt;
    self->descr = &(pvt->mip->descr);
    pvt->sessions_wrt = cfsp->sessions_wrt;

    return (0);
e5:
    RTPP_OBJ_DECREF(pvt->mip->log);
    rtpp_queue_destroy(pvt->mip->wthr.mod_q);
    pvt->mip->wthr.mod_q = NULL;
#if RTPP_CHECK_LEAKS
    if (rtpp_memdeb_dumpstats(pvt->memdeb_p, 1) != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "module '%s' leaked memory in the failed "
          "constructor", pvt->mip->descr.name);
    }
#endif
e4:
    RTPP_OBJ_DECREF(pvt->mip->wthr.sigterm);
    pvt->mip->wthr.sigterm = NULL;
e3:
#if RTPP_CHECK_LEAKS
    rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
e2:
    if (pvt->dmp != NULL)
        dlclose(pvt->dmp);
    pvt->mip = NULL;
e1:
    return (-1);
}

static void
rtpp_mif_dtor(struct rtpp_module_if_priv *pvt)
{

    if (pvt->mip != NULL) {
        if (pvt->started != 0) {
            /* First, stop the worker thread */
            RTPP_OBJ_INCREF(pvt->mip->wthr.sigterm);
            for (int r = -1; r < 0;) {
                r = rtpp_queue_put_item(pvt->mip->wthr.sigterm,
                  pvt->mip->wthr.mod_q);
            }
        }
    }
}

static void
rtpp_mif_kaput(struct rtpp_module_if *self)
{
    struct rtpp_module_if_priv *pvt;

    PUB2PVT(self, pvt);

    rtpp_module_if_fin(&(pvt->pub));
    if (pvt->started != 0) {
        /* First, wait for worker thread to terminate */
        pthread_join(pvt->mip->wthr.thread_id, NULL);
    }
    if (pvt->mip != NULL) {
        rtpp_queue_destroy(pvt->mip->wthr.mod_q);
        /* Then run module destructor (if any) */
        if (pvt->mip->proc.dtor != NULL && pvt->mpvt != NULL) {
            pvt->mip->proc.dtor(pvt->mpvt);
        }
        RTPP_OBJ_DECREF(pvt->mip->log);
        RTPP_OBJ_DECREF(pvt->mip->wthr.sigterm);

#if RTPP_CHECK_LEAKS
        /* Check if module leaked any mem */
        if (rtpp_memdeb_dumpstats(pvt->memdeb_p, 1) != 0) {
            RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s' leaked memory after "
              "destruction", pvt->mip->descr.name);
        }
        rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
    }
    /* Unload and free everything */
    if (pvt->dmp != NULL)
        dlclose(pvt->dmp);
    free(pvt);
}

static void
rtpp_mif_run_acct(void *argp)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_wi *wi;
    int signum;
    const char *aname;
    const struct rtpp_acct_handlers *aap;

    pvt = (struct rtpp_module_if_priv *)argp;
    aap = pvt->mip->aapi;
    for (;;) {
        wi = rtpp_queue_get_item(pvt->mip->wthr.mod_q, 0);
        if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
            signum = rtpp_wi_sgnl_get_signum(wi);
            RTPP_OBJ_DECREF(wi);
            if (signum == SIGTERM) {
                break;
            }
            continue;
        }
        aname = rtpp_wi_apis_getname(wi);
        if (aname == do_acct_aname) {
            struct rtpp_acct *rap;

            rtpp_wi_apis_getnamearg(wi, (void **)&rap, sizeof(rap));
            if (aap->on_session_end.func != NULL)
                aap->on_session_end.func(pvt->mpvt, rap);
            RTPP_OBJ_DECREF(rap);
        }
        if (aname == do_acct_rtcp_aname) {
            struct rtpp_acct_rtcp *rapr;

            rtpp_wi_apis_getnamearg(wi, (void **)&rapr, sizeof(rapr));
            if (aap->on_rtcp_rcvd.func != NULL)
                aap->on_rtcp_rcvd.func(pvt->mpvt, rapr);
            RTPP_OBJ_DECREF(rapr);
        }
        RTPP_OBJ_DECREF(wi);
    }
}

static void
rtpp_mif_do_acct(struct rtpp_module_if *self, struct rtpp_acct *acct)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_wi *wi;

    PUB2PVT(self, pvt);
    wi = rtpp_wi_malloc_apis(do_acct_aname, &acct, sizeof(acct));
    if (wi == NULL) {
        RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s': cannot allocate "
          "memory", pvt->mip->descr.name);
        return;
    }
    RTPP_OBJ_INCREF(acct);
    if (rtpp_queue_put_item(wi, pvt->mip->wthr.mod_q) == 0)
        return;
    RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s': accounting queue "
      "is full", pvt->mip->descr.name);
    RTPP_OBJ_DECREF(acct);
    RTPP_OBJ_DECREF(wi);
}

static void
rtpp_mif_do_acct_rtcp(struct rtpp_module_if *self, struct rtpp_acct_rtcp *acct)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_wi *wi;

    PUB2PVT(self, pvt);
    wi = rtpp_wi_malloc_apis(do_acct_rtcp_aname, &acct, sizeof(acct));
    if (wi == NULL) {
        RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s': cannot allocate "
          "memory", pvt->mip->descr.name);
        RTPP_OBJ_DECREF(acct);
        return;
    }
    if (rtpp_queue_put_item(wi, pvt->mip->wthr.mod_q) == 0)
        return;
    RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s': accounting queue "
      "is full", pvt->mip->descr.name);
    RTPP_OBJ_DECREF(acct);
    RTPP_OBJ_DECREF(wi);
}

#define PTH_CB(x) ((void *(*)(void *))(x))

static int
rtpp_mif_construct(struct rtpp_module_if *self, const struct rtpp_cfg *cfsp)
{
    struct rtpp_module_if_priv *pvt;

    PUB2PVT(self, pvt);
    if (pvt->mip->proc.ctor != NULL) {
        pvt->mpvt = pvt->mip->proc.ctor(cfsp);
        if (pvt->mpvt == NULL) {
            RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s' failed to initialize",
              pvt->mip->descr.name);
            return (-1);
        }
    }
    if (pvt->mip->proc.config != NULL) {
        if (pvt->mip->proc.config(pvt->mpvt) != 0) {
            RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "%p->config() method has failed: %s",
              self, pvt->mip->descr.name);
            if (pvt->mip->proc.dtor != NULL) {
                pvt->mip->proc.dtor(pvt->mpvt);
            }
            return (-1);
        }
    }
    return (0);
}

static int
rtpp_mif_start(struct rtpp_module_if *self, const struct rtpp_cfg *cfsp)
{
    struct rtpp_module_if_priv *pvt;

    PUB2PVT(self, pvt);
    if (pvt->mip->aapi == NULL && pvt->mip->wapi == NULL)
        return (0);
    if (pvt->mip->aapi != NULL) {
        if (pvt->mip->aapi->on_rtcp_rcvd.func != NULL) {
            struct packet_processor_if acct_rtcp_poi = {
                .descr = "acct_rtcp",
                .taste = packet_is_rtcp,
                .enqueue = acct_rtcp_enqueue,
                .arg = pvt
            };
            if (CALL_SMETHOD(cfsp->pproc_manager, reg, PPROC_ORD_WITNESS, &acct_rtcp_poi) < 0)
                return (-1);
        }
        if (pthread_create(&pvt->mip->wthr.thread_id, NULL,
          PTH_CB(&rtpp_mif_run_acct), pvt) != 0) {
            return (-1);
        }
    } else {
        pvt->mip->wthr.mpvt = pvt->mpvt;
        if (pthread_create(&pvt->mip->wthr.thread_id, NULL,
          PTH_CB(pvt->mip->wapi->main_thread), &pvt->mip->wthr) != 0) {
            return (-1);
        }
    }
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(pvt->mip->wthr.thread_id, pvt->mip->descr.name);
#endif
    pvt->started = 1;
    return (0);
}

static int
rtpp_mif_get_mconf(struct rtpp_module_if *self, struct rtpp_module_conf **mcpp)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_module_conf *rval;

    PUB2PVT(self, pvt);
    if (pvt->mip->proc.get_mconf == NULL) {
        *mcpp = NULL;
        return (0);
    }
    rval = pvt->mip->proc.get_mconf();
    if (rval == NULL) {
        return (-1);
    }
    *mcpp = rval;
    return (0);
}

static int
rtpp_mif_ul_subc_handle(const struct after_success_h_args *ashap,
  const struct rtpp_subc_ctx *ctxp)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_module_if *self;

    self = ashap->stat;
    PUB2PVT(self, pvt);
    return (pvt->mip->capi->ul_subc_handle(pvt->mpvt, ctxp));
}
