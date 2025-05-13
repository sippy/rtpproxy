/*
 * Copyright (c) 2020 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_list.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_modman.h"
#include "rtpp_module.h"
#include "rtpp_module_if.h"
#include "rtpp_modman_fin.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"

struct rtpp_modman_priv {
    struct rtpp_modman pub;
    struct rtpp_list all;
};

static void rtpp_modman_dtor(struct rtpp_modman_priv *);
static void rtpp_modman_insert(struct rtpp_modman *, struct rtpp_module_if *);
static int rtpp_modman_startall(struct rtpp_modman *, const struct rtpp_cfg *,
  const char **);
static unsigned int rtpp_modman_get_next_id(struct rtpp_modman *, unsigned int);
static void rtpp_modman_do_acct(struct rtpp_modman *, struct rtpp_acct *);
static int rtpp_modman_get_ul_subc_h(struct rtpp_modman *, unsigned int,
  unsigned int, struct after_success_h *);

struct rtpp_modman *
rtpp_modman_ctor(void)
{
    struct rtpp_modman_priv *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_modman_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pub.insert = rtpp_modman_insert;
    pvt->pub.startall = rtpp_modman_startall;
    pvt->pub.get_next_id = rtpp_modman_get_next_id;
    pvt->pub.do_acct = rtpp_modman_do_acct;
    pvt->pub.get_ul_subc_h = rtpp_modman_get_ul_subc_h;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_modman_dtor,
      pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static void
rtpp_modman_dtor(struct rtpp_modman_priv *pvt)
{
    struct rtpp_module_if *mif, *tmp;

    rtpp_modman_fin(&(pvt->pub));
    for (mif = RTPP_LIST_HEAD(&pvt->all); mif != NULL; mif = tmp) {
        tmp = RTPP_ITER_NEXT(mif);
        CALL_METHOD(mif, kaput);
        RTPP_OBJ_DECREF(mif);
    }
}

static void
rtpp_modman_insert(struct rtpp_modman *self, struct rtpp_module_if *mif)
{
    struct rtpp_modman_priv *pvt;

    PUB2PVT(self, pvt);
    mif->ids->module_idx = self->count.total;
    rtpp_list_append(&pvt->all, mif);
    self->count.total++;
    if (mif->has.do_acct)
        self->count.sess_acct++;
}

static int
rtpp_modman_startall(struct rtpp_modman *self, const struct rtpp_cfg *cfp,
  const char **failedmod)
{
    struct rtpp_module_if *mif;
    struct rtpp_modman_priv *pvt;

    PUB2PVT(self, pvt);
    for (mif = RTPP_LIST_HEAD(&pvt->all); mif != NULL; mif = RTPP_ITER_NEXT(mif)) {
        if (CALL_METHOD(mif, construct, cfp) != 0) {
            goto failed;
        }
        if (CALL_METHOD(mif, start, cfp) != 0) {
            goto failed;
        }
    }
    return (0);
failed:
    *failedmod = mif->descr->name;
    return (-1);
}

static unsigned int
rtpp_modman_get_next_id(struct rtpp_modman *self, unsigned int module_id)
{
    unsigned int ri;
    struct rtpp_modman_priv *pvt;

    ri = 1;
    PUB2PVT(self, pvt);
    for (struct rtpp_module_if *tmp = RTPP_LIST_HEAD(&pvt->all);
      tmp != NULL; tmp = RTPP_ITER_NEXT(tmp)) {
        if (tmp->descr->module_id != module_id)
            continue;
        ri += 1;
    }
    return (ri);
}

static void
rtpp_modman_do_acct(struct rtpp_modman *self, struct rtpp_acct *ap)
{
    struct rtpp_modman_priv *pvt;
    PUB2PVT(self, pvt);
    for (struct rtpp_module_if *tmp = RTPP_LIST_HEAD(&pvt->all);
      tmp != NULL; tmp = RTPP_ITER_NEXT(tmp)) {
        if (tmp->has.do_acct == 0)
            continue;
        CALL_METHOD(tmp, do_acct, ap);
    }
}

static int
rtpp_modman_get_ul_subc_h(struct rtpp_modman *self, unsigned int mod_id,
  unsigned int inst_id, struct after_success_h *ashp)
{
    struct rtpp_modman_priv *pvt;
    PUB2PVT(self, pvt);
    for (struct rtpp_module_if *tmp = RTPP_LIST_HEAD(&pvt->all);
      tmp != NULL; tmp = RTPP_ITER_NEXT(tmp)) {
        if (tmp->descr->module_id != mod_id || tmp->ids->instance_id != inst_id)
            continue;
        if (tmp->has.ul_subc_h == 0)
            break;
        ashp->handler = (after_success_t)tmp->ul_subc_handle;
        ashp->args.stat = tmp;
        return (0);
    }
    return (-1);
}
