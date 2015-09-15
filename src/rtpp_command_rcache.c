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
#include "rtpp_hash_table.h"
#include "rtpp_refcnt.h"
#include "rtpp_timed.h"
#include "rtpp_util.h"

#define	RTPP_RCACHE_CPERD	3.0

struct rtpp_cmd_rcache_pvt {
    struct rtpp_cmd_rcache_obj pub;
    double min_ttl;
    struct rtpp_hash_table_obj *ht;
    struct rtpp_timed_obj *rtpp_timed_cf_save;
    struct rtpp_wi *timeout;
};

struct rtpp_cmd_rcache_entry {
    char *reply;
    double etime;
};

static void rtpp_cmd_rcache_cleanup(double, void *);
static void rtpp_cmd_rcache_insert(struct rtpp_cmd_rcache_obj *, const char *,
  const char *, double);
int rtpp_cmd_rcache_lookup(struct rtpp_cmd_rcache_obj *, const char *,
  char *, int);
void rtpp_cmd_rcache_dtor(struct rtpp_cmd_rcache_obj *);

struct rtpp_cmd_rcache_obj *
rtpp_cmd_rcache_ctor(struct rtpp_timed_obj *rtpp_timed_cf, double min_ttl)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_cmd_rcache_pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    pvt->ht = rtpp_hash_table_ctor();
    if (pvt->ht == NULL) {
        goto e0;
    }
    pvt->timeout = CALL_METHOD(rtpp_timed_cf, schedule, RTPP_RCACHE_CPERD,
      rtpp_cmd_rcache_cleanup, NULL, pvt);
    if (pvt->timeout == NULL) {
        goto e0;
    }
    pvt->min_ttl = min_ttl;
    pvt->rtpp_timed_cf_save = rtpp_timed_cf;
    pvt->pub.insert = rtpp_cmd_rcache_insert;
    pvt->pub.lookup = rtpp_cmd_rcache_lookup;
    pvt->pub.dtor = rtpp_cmd_rcache_dtor;
    return (&pvt->pub);
e0:
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
rtpp_cmd_rcache_insert(struct rtpp_cmd_rcache_obj *pub, const char *cookie,
  const char *reply, double ctime)
{
    struct rtpp_cmd_rcache_pvt *pvt;
    struct rtpp_cmd_rcache_entry *rep;
    struct rtpp_refcnt_obj *rco;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    rep = rtpp_zmalloc(sizeof(struct rtpp_cmd_rcache_entry));
    if (rep == NULL) {
        return;
    }
    rep->reply = strdup(reply);
    if (rep->reply == NULL) {
        goto e1;
    }
    rep->etime = ctime + pvt->min_ttl;
    rco = rtpp_refcnt_ctor(rep, rtpp_cmd_rcache_entry_free);
    if (rco == NULL) {
        goto e3;
    }
    CALL_METHOD(pvt->ht, append_refcnt, cookie, rco);
    /*
     * append_refcnt() either takes ownership in which case it incs refcount
     * or it drops the ball in which it does not, so we release rco and set
     * it free.
     */
    CALL_METHOD(rco, decref);
    return;
e3:
    free(rep->reply);
e1:
    free(rep);
}

int
rtpp_cmd_rcache_lookup(struct rtpp_cmd_rcache_obj *pub, const char *cookie,
  char *rbuf, int rblen)
{
    struct rtpp_cmd_rcache_pvt *pvt;
    struct rtpp_cmd_rcache_entry *rep;
    struct rtpp_refcnt_obj *rco;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    rco = CALL_METHOD(pvt->ht, find, cookie);
    if (rco == NULL) {
        return (0);
    }
    /*
     * "find" method returns object that has been incref'ed, so make sure
     * to decref when we've done with it.
     */
    rep = CALL_METHOD(rco, getdata);
    strncpy(rbuf, rep->reply, rblen);
    CALL_METHOD(rco, decref);
    return (1);
}

void
rtpp_cmd_rcache_dtor(struct rtpp_cmd_rcache_obj *pub)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = (struct rtpp_cmd_rcache_pvt *)pub;
    CALL_METHOD(pvt->rtpp_timed_cf_save, cancel, pvt->timeout);
    CALL_METHOD(pvt->ht, dtor);
    free(pvt);
}

static int
rtpp_cmd_rcache_ematch(struct rtpp_refcnt_obj *rco, void *p)
{
    struct rtpp_cmd_rcache_entry *rep;
    double *ctimep;

    /*
     * This method does not need us to bump ref, since we are in the
     * context of the rtpp_hash_table, which hold its own ref.
     */
    ctimep = (double *)p;
    rep = CALL_METHOD(rco, getdata);
    if (rep->etime < *ctimep) {
        return (1);
    }
    return (0);
}

static void
rtpp_cmd_rcache_cleanup(double ctime, void *p)
{
    struct rtpp_cmd_rcache_pvt *pvt;

    pvt = (struct rtpp_cmd_rcache_pvt *)p;
    CALL_METHOD(pvt->ht, expire, rtpp_cmd_rcache_ematch, &ctime);
    pvt->timeout = CALL_METHOD(pvt->rtpp_timed_cf_save, schedule,
      RTPP_RCACHE_CPERD, rtpp_cmd_rcache_cleanup, NULL, pvt);
}
