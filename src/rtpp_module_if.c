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

#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_log.h"
#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#define MODULE_IF_CODE
#include "rtpp_module.h"
#include "rtpp_module_if.h"
#include "rtpp_module_if_fin.h"
#include "rtpp_refcnt.h"
#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"
#endif

struct rtpp_module_if_priv {
    struct rtpp_module_if pub;
    void *dmp;
    struct rtpp_minfo *mip;
    struct rtpp_module_priv *mpvt;
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

#define PUB2PVT(pubp) \
  ((struct rtpp_module_if_priv *)((char *)(pubp) - offsetof(struct rtpp_module_if_priv, pub)))

struct rtpp_module_if *
rtpp_module_if_ctor(struct rtpp_cfg_stable *cfsp, struct rtpp_log *log,
  const char *mpath)
{
    struct rtpp_refcnt *rcnt;
    struct rtpp_module_if_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_module_if_priv), &rcnt);
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.rcnt = rcnt;
    pvt->dmp = dlopen(mpath, RTLD_NOW);
    if (pvt->dmp == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "can't dlopen(%s): %s", mpath, dlerror());
        goto e1;
    }
    pvt->mip = dlsym(pvt->dmp, "rtpp_module");
    if (pvt->mip == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "can't find 'rtpp_module' symbol in the %s"
          ": %s", mpath, dlerror());
        goto e2;
    }
    if (!MI_VER_CHCK(pvt->mip)) {
        RTPP_LOG(log, RTPP_LOG_ERR, "incompatible API version in the %s, "
          "consider recompiling the module", mpath);
        goto e2;
    }

#if RTPP_CHECK_LEAKS
    pvt->mip->malloc = &rtpp_memdeb_malloc;
    pvt->mip->free = &rtpp_memdeb_free;
    pvt->mip->realloc = &rtpp_memdeb_realloc;
    pvt->mip->strdup = &rtpp_memdeb_strdup;
    pvt->mip->asprintf = &rtpp_memdeb_asprintf;
    pvt->mip->vasprintf = &rtpp_memdeb_vasprintf;
    pvt->memdeb_p = rtpp_memdeb_init();
    rtpp_memdeb_setlog(pvt->memdeb_p, log);
#else
    pvt->mip->malloc = (rtpp_module_malloc_t)&malloc;
    pvt->mip->free = (rtpp_module_free_t)&free;
    pvt->mip->realloc = (rtpp_module_realloc_t)&realloc;
    pvt->mip->strdup = (rtpp_module_strdup_t)&strdup;
    pvt->mip->asprintf = rtpp_module_asprintf;
    pvt->mip->vasprintf = rtpp_module_vasprintf;
#endif
    if (pvt->memdeb_p == NULL) {
        goto e2;
    }
    pvt->mip->memdeb_p = pvt->memdeb_p;

    if (pvt->mip->ctor != NULL) {
        pvt->mpvt = pvt->mip->ctor(cfsp);
        if (pvt->mpvt == NULL) {
            RTPP_LOG(log, RTPP_LOG_ERR, "module '%s' failed to initialize",
              pvt->mip->name);
            goto e3;
        }
    }
    CALL_METHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_mif_dtor,
      pvt);
    return ((&pvt->pub));
e3:
#if RTPP_CHECK_LEAKS
    rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
e2:
    dlclose(pvt->dmp);
e1:
    CALL_METHOD(rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_mif_dtor(struct rtpp_module_if_priv *pvt)
{

    rtpp_module_if_fin(&(pvt->pub));
    if (pvt->mip->dtor != NULL) {
        pvt->mip->dtor(pvt->mpvt);
    }
#if RTPP_CHECK_LEAKS
    rtpp_memdeb_dumpstats(pvt->memdeb_p, 1);
    rtpp_memdeb_dtor(pvt->memdeb_p);
#endif
    dlclose(pvt->dmp);
    free(pvt);
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
