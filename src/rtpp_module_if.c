/*
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_log.h"
#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#define MODULE_IF_CODE
#include "rtpp_module.h"
#include "rtpp_module_if.h"
#include "rtpp_module_if_fin.h"
#include "rtpp_queue.h"
#include "rtpp_refcnt.h"
#include "rtpp_wi.h"
#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"
#endif

struct rtpp_module_if_priv {
    struct rtpp_module_if pub;
    void *dmp;
    struct rtpp_minfo *mip;
    struct rtpp_module_priv *mpvt;
    struct rtpp_log *log;
    struct rtpp_wi *sigterm;
    pthread_t thread_id;
    struct rtpp_queue *req_q;
    /* Privary version of the module's memdeb_p, store it here */
    /* just in case module screws it up                        */
    void *memdeb_p;
};

static void rtpp_mif_dtor(struct rtpp_module_if_priv *);
#if !RTPP_CHECK_LEAKS
static int rtpp_module_asprintf(char **, const char *, void *, const char *,
  int, const char *, ...);
static int rtpp_module_vasprintf(char **, const char *, void *, const char *,
  int, const char *, va_list);
#endif
static void rtpp_mif_run(void *);
static void rtpp_mif_do_acct(struct rtpp_module_if *, struct rtpp_acct *);

#define PUB2PVT(pubp) \
  ((struct rtpp_module_if_priv *)((char *)(pubp) - offsetof(struct rtpp_module_if_priv, pub)))

static const char *do_acct_aname = "do_acct";

struct rtpp_module_if *
rtpp_module_if_ctor(struct rtpp_cfg_stable *cfsp, struct rtpp_log *log,
  const char *mpath)
{
    struct rtpp_refcnt *rcnt;
    struct rtpp_module_if_priv *pvt;
    const char *derr;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_module_if_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;
    pvt->dmp = dlopen(mpath, RTLD_NOW);
    if (pvt->dmp == NULL) {
        derr = dlerror();
        if (strstr(derr, mpath) == NULL) {
            RTPP_LOG(log, RTPP_LOG_ERR, "can't dlopen(%s): %s", mpath, derr);
        } else {
            RTPP_LOG(log, RTPP_LOG_ERR, "can't dlopen() module: %s", derr);
        }
        goto e1;
    }
    pvt->mip = dlsym(pvt->dmp, "rtpp_module");
    if (pvt->mip == NULL) {
        derr = dlerror();
        if (strstr(derr, mpath) == NULL) {
            RTPP_LOG(log, RTPP_LOG_ERR, "can't find 'rtpp_module' symbol in the %s"
              ": %s", mpath, derr);
        } else {
            RTPP_LOG(log, RTPP_LOG_ERR, "can't find 'rtpp_module' symbol: %s",
              derr);
        }
        goto e2;
    }
    if (!MI_VER_CHCK(pvt->mip)) {
        RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
          "consider recompiling the module", mpath);
        goto e2;
    }

#if RTPP_CHECK_LEAKS
    pvt->mip->_malloc = &rtpp_memdeb_malloc;
    pvt->mip->_zmalloc = &rtpp_zmalloc_memdeb;
    pvt->mip->_free = &rtpp_memdeb_free;
    pvt->mip->_realloc = &rtpp_memdeb_realloc;
    pvt->mip->_strdup = &rtpp_memdeb_strdup;
    pvt->mip->_asprintf = &rtpp_memdeb_asprintf;
    pvt->mip->_vasprintf = &rtpp_memdeb_vasprintf;
    pvt->memdeb_p = rtpp_memdeb_init();
    rtpp_memdeb_setlog(pvt->memdeb_p, log);
    if (pvt->memdeb_p == NULL) {
        goto e2;
    }
    /* We make a copy, so that the module cannot screw us up */
    pvt->mip->memdeb_p = pvt->memdeb_p;
#else
    pvt->mip->_malloc = (rtpp_module_malloc_t)&malloc;
    pvt->mip->_zmalloc = (rtpp_module_zmalloc_t)&rtpp_zmalloc;
    pvt->mip->_free = (rtpp_module_free_t)&free;
    pvt->mip->_realloc = (rtpp_module_realloc_t)&realloc;
    pvt->mip->_strdup = (rtpp_module_strdup_t)&strdup;
    pvt->mip->_asprintf = rtpp_module_asprintf;
    pvt->mip->_vasprintf = rtpp_module_vasprintf;
#endif
    pvt->sigterm = rtpp_wi_malloc_sgnl(SIGTERM, NULL, 0);
    if (pvt->sigterm == NULL) {
        goto e3;
    }
    pvt->req_q = rtpp_queue_init(1, "rtpp_module_if(%s)", pvt->mip->name);
    if (pvt->req_q == NULL) {
        goto e4;
    }
    CALL_SMETHOD(log->rcnt, incref);
    pvt->mip->log = log;
    if (pvt->mip->ctor != NULL) {
        pvt->mpvt = pvt->mip->ctor(cfsp);
        if (pvt->mpvt == NULL) {
            RTPP_LOG(log, RTPP_LOG_ERR, "module '%s' failed to initialize",
              pvt->mip->name);
            goto e5;
        }
    }
    if (pvt->mip->on_session_end.argsize != rtpp_acct_OSIZE()) {
        RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
          "consider recompiling the module", mpath);
        goto e6;
    }

    if (pthread_create(&pvt->thread_id, NULL,
      (void *(*)(void *))&rtpp_mif_run, pvt) != 0) {
        goto e6;
    }
    pvt->pub.do_acct = &rtpp_mif_do_acct;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_mif_dtor,
      pvt);
    return ((&pvt->pub));
e6:
    if (pvt->mip->dtor != NULL) {
        pvt->mip->dtor(pvt->mpvt);
    }
e5:
    CALL_SMETHOD(pvt->mip->log->rcnt, decref);
    rtpp_queue_destroy(pvt->req_q);
#if RTPP_CHECK_LEAKS
    if (rtpp_memdeb_dumpstats(pvt->memdeb_p, 1) != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "module '%s' leaked memory in the failed "
          "constructor", pvt->mip->name);
    }
#endif
e4:
    rtpp_wi_free(pvt->sigterm);
e3:
#if RTPP_CHECK_LEAKS
    rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
e2:
    dlclose(pvt->dmp);
e1:
    CALL_SMETHOD(rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_mif_dtor(struct rtpp_module_if_priv *pvt)
{

    rtpp_module_if_fin(&(pvt->pub));
    /* First, stop the worker thread and wait for it to terminate */
    rtpp_queue_put_item(pvt->sigterm, pvt->req_q);
    pthread_join(pvt->thread_id, NULL);
    rtpp_queue_destroy(pvt->req_q);

    /* Then run module destructor (if any) */
    if (pvt->mip->dtor != NULL) {
        pvt->mip->dtor(pvt->mpvt);
    }
    CALL_SMETHOD(pvt->mip->log->rcnt, decref);

#if RTPP_CHECK_LEAKS
    /* Check if module leaked any mem */
    if (rtpp_memdeb_dumpstats(pvt->memdeb_p, 1) != 0) {
        RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s' leaked memory after "
          "destruction", pvt->mip->name);
    }
    rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
    /* Unload and free everything */
    dlclose(pvt->dmp);
    free(pvt);
}

static void
rtpp_mif_run(void *argp)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_wi *wi;
    int signum;
    const char *aname;
    struct rtpp_acct *rap;

    pvt = (struct rtpp_module_if_priv *)argp;
    for (;;) {
        wi = rtpp_queue_get_item(pvt->req_q, 0);
        if (rtpp_wi_get_type(wi) == RTPP_WI_TYPE_SGNL) {
            signum = rtpp_wi_sgnl_get_signum(wi);
            rtpp_wi_free(wi);
            if (signum == SIGTERM) {
                break;
            }
            continue;
        }
        aname = rtpp_wi_apis_getnamearg(wi, (void **)&rap, sizeof(rap));
        if (aname == do_acct_aname) {
            pvt->mip->on_session_end.func(pvt->mpvt, rap);
        }
        CALL_SMETHOD(rap->rcnt, decref);
        rtpp_wi_free(wi);
    }
}

static void
rtpp_mif_do_acct(struct rtpp_module_if *self, struct rtpp_acct *acct)
{
    struct rtpp_module_if_priv *pvt;
    struct rtpp_wi *wi;

    pvt = PUB2PVT(self);
    wi = rtpp_wi_malloc_apis(do_acct_aname, &acct, sizeof(acct));
    if (wi == NULL) {
        RTPP_LOG(pvt->mip->log, RTPP_LOG_ERR, "module '%s': cannot allocate "
          "memory", pvt->mip->name);
        return;
    }
    CALL_SMETHOD(acct->rcnt, incref);
    rtpp_queue_put_item(wi, pvt->req_q);
}

#if !RTPP_CHECK_LEAKS
static int
rtpp_module_asprintf(char **pp, const char *fmt, void *p, const char *fname,
  int linen, const char *funcn, ...)
{
    va_list ap;
    int rval;

    va_start(ap, funcn);
    rval = vasprintf(pp, fmt, ap);
    va_end(ap);
    return (rval);
}

static int
rtpp_module_vasprintf(char **pp, const char *fmt, void *p, const char *fname,
  int linen, const char *funcn, va_list ap)
{
    int rval;

    rval = vasprintf(pp, fmt, ap);
    return (rval);
}
#endif
