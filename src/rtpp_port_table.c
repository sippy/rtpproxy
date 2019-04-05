/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
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

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_port_table.h"
#include "rtpp_port_table_fin.h"

struct rtpp_ptbl_priv {
    struct rtpp_port_table pub;
    pthread_mutex_t lock;
    int port_table_len;
    int port_table_idx;
    uint16_t *port_table;
    uint16_t port_ctl;
    int seq_ports;
};

static void rtpp_ptbl_dtor(struct rtpp_ptbl_priv *);
static int rtpp_ptbl_get_port(struct rtpp_port_table *, rtpp_pt_use_t, void *);

#define PUB2PVT(pubp) \
  ((struct rtpp_ptbl_priv *)((char *)(pubp) - offsetof(struct rtpp_ptbl_priv, pub)))

struct rtpp_port_table *
rtpp_port_table_ctor(int port_min, int port_max, int seq_ports, uint16_t port_ctl)
{
    struct rtpp_ptbl_priv *pvt;
    int i, j;
    uint16_t portnum;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_ptbl_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    if (pthread_mutex_init(&pvt->lock, NULL) != 0) {
        goto e1;
    }
    pvt->port_table_len = ((port_max - port_min) / 2) + 1;
    pvt->port_table = malloc(sizeof(uint16_t) * pvt->port_table_len);
    if (pvt->port_table == NULL) {
        goto e2;
    }
    pvt->port_ctl = port_ctl;

    /* Generate linear table */
    portnum = port_min;
    for (i = 0; i < pvt->port_table_len; i += 1) {
        pvt->port_table[i] = portnum;
        portnum += 2;
    }
    if (seq_ports == 0) {
        /* Shuffle elements ramdomly */
        for (i = 0; i < pvt->port_table_len; i += 1) {
            j = random() % pvt->port_table_len;
            portnum = pvt->port_table[i];
            pvt->port_table[i] = pvt->port_table[j];
            pvt->port_table[j] = portnum;
        }
    }
    pvt->seq_ports = seq_ports;
    /* Set the last used element to be the last element */
    pvt->port_table_idx = pvt->port_table_len - 1;

    pvt->pub.get_port = &rtpp_ptbl_get_port;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_ptbl_dtor,
      pvt);
    return ((&pvt->pub));

e2:
    pthread_mutex_destroy(&pvt->lock);
e1:
    CALL_SMETHOD(pvt->pub.rcnt, decref);
    free(pvt);
e0:
    return (NULL);
}

static void
rtpp_ptbl_dtor(struct rtpp_ptbl_priv *pvt)
{

    rtpp_port_table_fin(&pvt->pub);
    pthread_mutex_destroy(&pvt->lock);
    free(pvt->port_table);
    free(pvt);
}

static int
rtpp_ptbl_get_port(struct rtpp_port_table *self, rtpp_pt_use_t use_port, void *uarg)
{
    struct rtpp_ptbl_priv *pvt;
    int i, j, idx, rval;
    uint16_t port;

    pvt = PUB2PVT(self);

    pthread_mutex_lock(&pvt->lock);
    for (i = 1; i < pvt->port_table_len; i++) {
        idx = (pvt->port_table_idx + i) % pvt->port_table_len;
        port = pvt->port_table[idx];
        if (port == pvt->port_ctl || port == (pvt->port_ctl - 1))
            continue;
        rval = use_port(port, uarg);
        if (!pvt->seq_ports) {
            /* Shuffle table as we go, so we are not easy to outguess */
            j = random() % pvt->port_table_len;
            pvt->port_table[idx] = pvt->port_table[j];
            pvt->port_table[j] = port;
        }
        if (rval == RTPP_PTU_OK) {
            pvt->port_table_idx = idx;
            pthread_mutex_unlock(&pvt->lock);
            return 0;
        }
        if (rval != RTPP_PTU_ONEMORE) {
            pvt->port_table_idx = idx;
            break;
        }
    }
    pthread_mutex_unlock(&pvt->lock);
    return -1;
}
