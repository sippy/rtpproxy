/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bulk_net/module/syscall.h"

#include "rtpp_defines.h"
#include "rtp.h"
#include "rtpp_bulk_netio.h"

static int sendto_bulk_sycallno = -1;
static int recvfrom_bulk_sycallno;

struct rtpp_bnet_opipe {
    int plen;
    int clen;
    int compat;
    int dmode;
    struct sendto_s *ss_send;
    struct rtp_packet **pkts;
};

struct rtpp_bnet_ipipe_sock {
    int s;
    int ndrain;
    void *cb_func_arg;
};

struct rtpp_bnet_ipipe {
    int plen;
    int compat;
    int nsocks;
    int usocks;
    struct recvfrom_s *ss_recv;
    struct rtpp_bnet_ipipe_sock *socks;
};

struct rtpp_bnet_opipe *
rtpp_bulk_netio_opipe_new(int plen, int freepkts, int dmode)
{
    struct rtpp_bnet_opipe *op;
    int msize;

    msize = sizeof(struct rtpp_bnet_opipe) + (sizeof(struct sendto_s) * plen);
    if (freepkts != 0) {
        msize += (sizeof(struct rtp_packet *) * plen);
    }

    op = malloc(msize);
    if (op == NULL) {
        return (NULL);
    }
    memset(op, 0, msize);
    op->ss_send = (struct sendto_s *)(op + 1);
    if (freepkts != 0) {
        op->pkts = (void *)((uint8_t *)op->ss_send + (sizeof(struct sendto_s) * plen));
    } else {
        op->pkts = NULL;
    }
    op->plen = plen;
    op->clen = 0;
    op->compat = (sendto_bulk_sycallno == -1) ? 1 : 0;
    op->dmode = dmode;

    return (op);
}

struct rtpp_bnet_ipipe *
rtpp_bulk_netio_ipipe_new(int plen)
{
    struct rtpp_bnet_ipipe *ip;
    int msize;

    msize = sizeof(struct rtpp_bnet_ipipe) + (sizeof(struct recvfrom_s) * plen);

    ip = malloc(msize);
    if (ip == NULL) {
        return (NULL);
    }
    memset(ip, 0, msize);

    ip->nsocks = plen * 4;
    msize = (sizeof(struct rtpp_bnet_ipipe_sock) * ip->nsocks);
    ip->socks = malloc(msize);
    if (ip->socks == NULL) {
        free(ip);
        return (NULL);
    }

    ip->ss_recv = (struct recvfrom_s *)(ip + 1);
    ip->plen = plen;
    ip->usocks = 0;
    ip->compat = (sendto_bulk_sycallno == -1) ? 1 : 0;

    return (ip);
}

int
rtpp_bulk_netio_ipipe_add_s(struct rtpp_bnet_ipipe *ip, int s, \
  int ndrain, void *cb_func_arg)
{
    struct rtpp_bnet_ipipe_sock *iss;

    if (ip->usocks == ip->nsocks) {
        /* Make up some more room */
        iss = realloc(ip->socks, (sizeof(struct rtpp_bnet_ipipe_sock) * ip->nsocks * 2));
        if (iss == NULL) {
            return (-1);
        }
        ip->nsocks *= 2;
        ip->socks = iss;
        iss += ip->usocks;
    } else {
        iss = &ip->socks[ip->usocks];
    }
    
    iss->s = s;
    iss->ndrain = ndrain;
    iss->cb_func_arg = cb_func_arg;
    ip->usocks += 1;
    return (0);
}

static void
rtpp_bulk_netio_ipipe_proc(struct recvfrom_s *ss_recv, \
  struct rtpp_bnet_ipipe_sock **iss, ipipe_cb_t proc_func, int clen)
{
    int i;
    struct rtp_packet *packet;

    for (i = 0; i < clen; i++) {
        packet = rtp_recv(ss_recv[i].args.s);
        if (packet == NULL) {
            /* Move on to the next session */
            iss[i]->ndrain = -1;
            continue;
        }
        proc_func(packet, iss[i]->cb_func_arg);
    }
}


void
rtpp_bulk_netio_ipipe_pump(struct rtpp_bnet_ipipe *ip, ipipe_cb_t proc_func)
{
    int i, clen, ndrain;
    struct recvfrom_s *ss_recv;
    struct rtpp_bnet_ipipe_sock **iss;

    clen = 0;
    ss_recv = ip->ss_recv;
    iss = alloca(sizeof(struct rtpp_bnet_ipipe_sock *) * ip->plen);
    do {
        ndrain = 0;
        for (i = 0; i < ip->usocks; i++) {
            if (ip->socks[i].ndrain <= 0)
                continue;
            iss[clen] = &ip->socks[i];
            iss[clen]->ndrain -= 1;
            ndrain += 1;
            ss_recv[clen].args.s = ip->socks[i].s;
            clen += 1;
            if (clen < ip->plen)
                continue;
            rtpp_bulk_netio_ipipe_proc(ss_recv, iss, proc_func, clen);
            clen = 0;
        }
    } while (ndrain > 0);
    if (clen > 0)
        rtpp_bulk_netio_ipipe_proc(ss_recv, iss, proc_func, clen);
}

void
rtpp_bulk_netio_ipipe_reset(struct rtpp_bnet_ipipe *ip)
{

    ip->usocks = 0;
}

void
rtpp_bulk_netio_ipipe_destroy(struct rtpp_bnet_ipipe *ip)
{

    free(ip->socks);
    free(ip);
}

int
rtpp_bulk_netio_opipe_destroy(struct rtpp_bnet_opipe *op)
{
    int rval;

    rval = rtpp_bulk_netio_opipe_flush(op);
    free(op);
    return (rval);
}

int
rtpp_bulk_netio_opipe_flush(struct rtpp_bnet_opipe *op)
{
    int rval, i;

    if (op->clen <= 0)
        return (op->clen);
    if (op->compat == 0) {
        rval = syscall(sendto_bulk_sycallno, op->ss_send, op->clen);
    } else {
        struct sendto_s *ss_send;

        for (i = 0; i < op->clen; i++) {
            ss_send = &op->ss_send[i];
            sendto(ss_send->args.s, ss_send->args.buf, ss_send->args.len,
              ss_send->args.flags, (const struct sockaddr *)ss_send->args.to,
              ss_send->args.tolen);
        }
    }
    if (op->pkts != NULL) {
        for (i = 0; i < op->clen; i++) {
            if (op->pkts[i] == NULL)
                continue;
            rtp_packet_free(op->pkts[i]);
            op->pkts[i] = NULL;
        }
    }
    op->clen = 0;
    return (rval);
}

int
rtpp_bulk_netio_opipe_sendto(struct rtpp_bnet_opipe *op, int s, const void *msg, \
  size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
    struct sendto_s *ss_send;

    ss_send = &op->ss_send[op->clen];
    ss_send->args.s = s;
    ss_send->args.buf = (void *)msg;
    ss_send->args.len = len;
    ss_send->args.flags = flags;
    ss_send->args.to = (void *)to;
    ss_send->args.tolen = tolen;
    ss_send->rval = EINVAL;
    op->clen += 1;
    if (op->clen < op->plen)
        return (0);
    
    return (rtpp_bulk_netio_opipe_flush(op));
}

int
rtpp_bulk_netio_opipe_send_pkt(struct rtpp_bnet_opipe *op, int s, \
  const struct sockaddr *to, socklen_t tolen, struct rtp_packet *pkt)
{

    assert(op->pkts != NULL);
    assert(op->pkts[op->clen] == NULL);

    if (op->dmode != 0 && pkt->size < LBR_THRS) {
        rtpp_bulk_netio_opipe_sendto(op, s, (const void *)&(pkt->data.buf), pkt->size, \
          0, to, tolen);
    }
    op->pkts[op->clen] = pkt;
    return (rtpp_bulk_netio_opipe_sendto(op, s, (const void *)&(pkt->data.buf), pkt->size, \
      0, to, tolen));
}

int
rtpp_bulk_netio_init()
{
    int modid;
    struct module_stat stat;

    stat.version = sizeof(stat);
    modid = modfind("net_bulk");
    if (modid < 0) {
        warn("modfind(net_bulk)");
        return (-1);
    }
    if (modstat(modid, &stat) != 0) {
        warn("modstat(net_bulk)");
        return (-1);
    }
    sendto_bulk_sycallno = stat.data.intval;
    recvfrom_bulk_sycallno = stat.data.intval + 1;

    return (0);
}
