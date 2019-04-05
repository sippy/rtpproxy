/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_command_rcache.h"
#include "rtpp_command_rcache_fin.h"
#include "rtpp_hash_table.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"

#define	RTPP_RCACHE_CPERD	3.0

struct rtpp_cmd_rcache_pvt {
    struct rtpp_cmd_rcache pub;
    double min_ttl;
    struct rtpp_hash_table *ht;
    struct rtpp_timed_task *timeout;
    int timeout_rval;
};

struct rtpp_cmd_rcache_entry {
    char *reply;
    double etime;
    struct {
        struct rtpp_refcnt *rcnt;
    } pub;
};

static enum rtpp_timed_cb_rvals rtpp_cmd_rcache_cleanup(double, void *);
static void rtpp_cmd_rcache_insert(struct rtpp_cmd_rcache *, const char *,
  const char *, double);
int rtpp_cmd_rcache_lookup(struct rtpp_cmd_rcache *, const char *,
  char *, int);
static void rtpp_cmd_rcache_dtor(struct rtpp_cmd_rcache_pvt *);
static void rtpp_cmd_rcache_shutdown(struct rtpp_cmd_rcache *);

struct rtpp_cmd_rcache *
rtpp_cmd_rcache_ctor(struct rtpp_timed *rtpp_timed_cf, double min_ttl)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_cmd_rcache_pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
#if !defined(RTPP_DEBUG)
    pvt->ht = rtpp_hash_table_ctor(rtpp_ht_key_str_t, RTPP_HT_NODUPS);
#else
    pvt->ht = rtpp_hash_table_ctor(rtpp_ht_key_str_t, RTPP_HT_NODUPS |
      RTPP_HT_DUP_ABRT);
#endif
    if (pvt->ht == NULL) {
        goto e0;
    }
    pvt->timeout = CALL_SMETHOD(rtpp_timed_cf, schedule_rc, RTPP_RCACHE_CPERD,
      pvt->pub.rcnt, rtpp_cmd_rcache_cleanup, NULL, pvt);
    if (pvt->timeout == NULL) {
        goto e2;
    }
    pvt->min_ttl = min_ttl;
    pvt->timeout_rval = CB_MORE;
    pvt->pub.insert = &rtpp_cmd_rcache_insert;
    pvt->pub.lookup = &rtpp_cmd_rcache_lookup;
    pvt->pub.shutdown = &rtpp_cmd_rcache_shutdown;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_cmd_rcache_dtor,
      pvt);
    return (&pvt->pub);

e2:
    CALL_METHOD(pvt->ht, dtor);
e0:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
    return (NULL);
}

static void
rtpp_cmd_rcache_entry_free(void *p)
{
    struct rtpp_cmd_rcache_entry *rep;

    rep = (struct rtpp_cmd_rcache_entry *)p;
    free(rep->reply);
    free(rep);
}

static void
rtpp_cmd_rcache_insert(struct rtpp_cmd_rcache *pub, const char *cookie,
  const char *reply, double ctime)
{
    struct rtpp_cmd_rcache_pvt *pvt;
    struct rtpp_cmd_rcache_entry *rep;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    rep = rtpp_rzmalloc(sizeof(struct rtpp_cmd_rcache_entry), PVT_RCOFFS(rep));
    if (rep == NULL) {
        return;
    }
    rep->reply = strdup(reply);
    if (rep->reply == NULL) {
        goto e1;
    }
    rep->etime = ctime + pvt->min_ttl;
    CALL_SMETHOD(rep->pub.rcnt, attach, rtpp_cmd_rcache_entry_free, rep);
    CALL_METHOD(pvt->ht, append_refcnt, cookie, rep->pub.rcnt);
    /*
     * append_refcnt() either takes ownership in which case it incs refcount
     * or it drops the ball in which it does not, so we release rco and set
     * it free.
     */
    CALL_SMETHOD(rep->pub.rcnt, decref);
    return;
e1:
    CALL_SMETHOD(rep->pub.rcnt, decref);
    free(rep);
}

int
rtpp_cmd_rcache_lookup(struct rtpp_cmd_rcache *pub, const char *cookie,
  char *rbuf, int rblen)
{
    struct rtpp_cmd_rcache_pvt *pvt;
    struct rtpp_cmd_rcache_entry *rep;
    struct rtpp_refcnt *rco;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    rco = CALL_METHOD(pvt->ht, find, cookie);
    if (rco == NULL) {
        return (0);
    }
    /*
     * "find" method returns object that has been incref'ed, so make sure
     * to decref when we've done with it.
     */
    rep = CALL_SMETHOD(rco, getdata);
    strncpy(rbuf, rep->reply, rblen);
    CALL_SMETHOD(rco, decref);
    return (1);
}

static void
rtpp_cmd_rcache_shutdown(struct rtpp_cmd_rcache *pub)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    pvt->timeout_rval = CB_LAST;
    CALL_METHOD(pvt->timeout, cancel);
    CALL_SMETHOD(pvt->timeout->rcnt, decref);
    pvt->timeout = NULL;
}

void
rtpp_cmd_rcache_dtor(struct rtpp_cmd_rcache_pvt *pvt)
{

    rtpp_cmd_rcache_fin(&pvt->pub);
    CALL_METHOD(pvt->ht, dtor);
    free(pvt);
}

static int
rtpp_cmd_rcache_ematch(void *dp, void *ap)
{
    struct rtpp_cmd_rcache_entry *rep;
    double *ctimep;

    /*
     * This method does not need us to bump ref, since we are in the
     * context of the rtpp_hash_table, which hold its own ref.
     */
    ctimep = (double *)ap;
    rep = (struct rtpp_cmd_rcache_entry *)dp;
    if (rep->etime < *ctimep) {
        return (RTPP_HT_MATCH_DEL);
    }
    return (RTPP_HT_MATCH_CONT);
}

static enum rtpp_timed_cb_rvals
rtpp_cmd_rcache_cleanup(double ctime, void *p)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = (struct rtpp_cmd_rcache_pvt *)p;
    CALL_METHOD(pvt->ht, foreach, rtpp_cmd_rcache_ematch, &ctime);
    return (pvt->timeout_rval);
}
