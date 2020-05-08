/*
 * Copyright (c) 2019-2020 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_module.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_refcnt.h"
#include "rtpp_cfg.h"
#include "rtpp_stream.h"

struct rtpp_module_priv {
    struct rtpp_notify *notifier;
};

struct catch_dtmf_einfo {
    int pending;
    char digit;
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
    atomic_int pt;
    struct catch_dtmf_edata *edata;
    const struct rtpp_timeout_data *rtdp;
};

static struct rtpp_module_priv *rtpp_catch_dtmf_ctor(const struct rtpp_cfg *);
static void rtpp_catch_dtmf_dtor(struct rtpp_module_priv *);

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

struct rtpp_minfo rtpp_module = {
    .descr.name = "catch_dtmf",
    .descr.ver = MI_VER_INIT(),
    .descr.module_id = 3,
    .proc.ctor = rtpp_catch_dtmf_ctor,
    .proc.dtor = rtpp_catch_dtmf_dtor,
#ifdef RTPP_CHECK_LEAKS
    .memdeb_p = &MEMDEB_SYM
#endif
};

static void
rtpp_catch_dtmf_edata_dtor(void *p)
{

    mod_free(p);
}

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
    CALL_SMETHOD(edata->rcnt, attach, rtpp_catch_dtmf_edata_dtor, edata);
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

static struct rtpp_module_priv *
rtpp_catch_dtmf_ctor(const struct rtpp_cfg *cfsp)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    return (pvt);

#if 0
e1:
    mod_free(pvt);
#endif
e0:
    return (NULL);
}

static void
rtpp_catch_dtmf_dtor(struct rtpp_module_priv *pvt)
{

    mod_free(pvt);
    return;
}
