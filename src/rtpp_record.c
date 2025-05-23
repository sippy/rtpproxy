/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX)
#undef _GNU_SOURCE
#define __FAVOR_BSD
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_ip_chksum.h"
#include "rtpp_debug.h"
#include "rtpp_defines.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_network.h"
#include "rtpp_record.h"
#include "rtpp_record_fin.h"
#include "rtpp_record_adhoc.h"
#include "rtpp_record_private.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_time.h"
#include "rtpp_util.h"
#include "rtpp_pipe.h"
#include "rtpp_netaddr.h"
#include "rtpp_socket.h"
#include "advanced/pproc_manager.h"

enum record_mode {MODE_LOCAL_PKT, MODE_REMOTE_RTP, MODE_LOCAL_PCAP}; /* MODE_LOCAL_RTP/MODE_REMOTE_PKT? */

struct rtpp_record_channel {
    struct rtpp_record pub;
    pthread_mutex_t lock;
    char spath[PATH_MAX + 1];
    char rpath[PATH_MAX + 1];
    int fd;
    int needspool;
    char rbuf[4096];
    int rbuf_len;
    enum record_mode mode;
    int record_single_file;
    const char *proto;
    struct rtpp_log *log;
    struct rtpp_timestamp epoch;
};

static void rtpp_record_write(struct rtpp_record *, const struct pkt_proc_ctx *);
static void rtpp_record_close(struct rtpp_record_channel *);
static int get_hdr_size(const struct sockaddr *);

#if HAVE_SO_TS_CLOCK
#define ARRIVAL_TIME(rp, pp) (rp->epoch.wall + (pp->rtime.mono - rp->epoch.mono))
#else
#define ARRIVAL_TIME(rp, pp) (pp->rtime.wall)
#endif

DEFINE_SMETHODS(rtpp_record,
    .pktwrite = &rtpp_record_write
);

static int
ropen_remote_ctor_pa(const struct rtpp_cfg *cfg, struct rtpp_record_channel *rrc,
  const struct remote_copy_args *rap, struct rtpp_log *log, const char *rname, int is_rtcp)
{
    const char *cp = rap->rport;
    char tmp[8];
    int n, port;
    struct sockaddr_storage raddr;

    rrc->mode = MODE_REMOTE_RTP;
    rrc->needspool = 0;

    if (is_rtcp) {
        /* Handle RTCP (increase target port by 1) */
        port = atoi(rap->rport);
        if (port <= 0 || port > 65534) {
            RTPP_LOG(log, RTPP_LOG_ERR, "invalid port in the remote recording target specification");
            return (-1);
        }
        snprintf(tmp, sizeof(tmp), "%d", port + 1);
        cp = tmp;
    }

    n = resolve(sstosa(&raddr), AF_INET, rap->rhost, cp, 0);
    if (n != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "ropen: getaddrinfo: %s", gai_strerror(n));
        return (-1);
    }
    rrc->fd = CALL_SMETHOD(rap->fds[rap->idx], getfd);
    if (connect(rrc->fd, sstosa(&raddr), SA_LEN(sstosa(&raddr))) == -1) {
        RTPP_ELOG(log, RTPP_LOG_ERR, "ropen: can't connect socket");
        return (-1);
    }
    return (0);
}

struct rtpp_record *
rtpp_record_ctor(const struct rtpp_cfg *cfsp, const struct remote_copy_args *rap,
  struct rtpp_session *sp, const char *rname, int orig, int record_type)
{
    struct rtpp_record_channel *rrc;
    const char *sdir, *suffix1, *suffix2;
    int rval, remote;
    pcap_hdr_t pcap_hdr;

    remote = (rname != NULL && strncmp("udp:", rname, 4) == 0) ? 1 : 0;

    rrc = rtpp_rzmalloc(sizeof(*rrc), PVT_RCOFFS(rrc));
    if (rrc == NULL) {
        RTPP_ELOG(sp->log, RTPP_LOG_ERR, "can't allocate memory");
        goto e0;
    }
    if (pthread_mutex_init(&rrc->lock, NULL) != 0)
        goto e1;

    rrc->record_single_file = (record_type == RECORD_BOTH) ? 1 : 0;
    if (rrc->record_single_file != 0) {
        rrc->proto = "RTP/RTCP";
    } else {
        rrc->proto = (record_type == RECORD_RTP) ? "RTP" : "RTCP";
    }
    rrc->log = sp->log;
    RTPP_OBJ_INCREF(sp->log);
#if defined(RTPP_DEBUG)
    rrc->pub.smethods = rtpp_record_smethods;
#endif
    if (remote) {
        rval = ropen_remote_ctor_pa(cfsp, rrc, rap, sp->log, rname, (record_type == RECORD_RTCP));
        if (rval < 0) {
            goto e2;
        }
        RTPP_OBJ_BORROW(&rrc->pub, rap->fds[rap->idx]);
        CALL_SMETHOD(rrc->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_record_close,
          rrc);
        return (&rrc->pub);
    }

    if (cfsp->rdir == NULL) {
        RTPP_LOG(sp->log, RTPP_LOG_ERR, "directory for saving local recordings is not configured");
        goto e2;
    }

    if (cfsp->record_pcap != 0) {
        rrc->mode = MODE_LOCAL_PCAP;
    } else {
        rrc->mode = MODE_LOCAL_PKT;
    }

    if (rrc->record_single_file != 0) {
        suffix1 = suffix2 = "";
        if (rrc->mode == MODE_LOCAL_PCAP && rname == NULL) {
            suffix2 = ".pcap";
        }
    } else {
        suffix1 = (orig != 0) ? ".o" : ".a";
        suffix2 = (record_type == RECORD_RTP) ? ".rtp" : ".rtcp";
    }
    if (cfsp->sdir == NULL) {
        sdir = cfsp->rdir;
        rrc->needspool = 0;
    } else {
        sdir = cfsp->sdir;
        rrc->needspool = 1;
        if (rname == NULL) {
            sprintf(rrc->rpath, "%s/%.*s=%.*s%s%s", cfsp->rdir, (int)sp->call_id->len,
              sp->call_id->s, (int)sp->from_tag_nmn->len, sp->from_tag_nmn->s,
              suffix1, suffix2);
        } else {
            sprintf(rrc->rpath, "%s/%s%s", cfsp->rdir, rname, suffix2);
        }
    }
    if (rname == NULL) {
        sprintf(rrc->spath, "%s/%.*s=%.*s%s%s", sdir, (int)sp->call_id->len,
          sp->call_id->s, (int)sp->from_tag_nmn->len, sp->from_tag_nmn->s,
          suffix1, suffix2);
    } else {
        sprintf(rrc->spath, "%s/%s%s", sdir, rname, suffix2);
    }
    rrc->fd = open(rrc->spath, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (rrc->fd == -1) {
        RTPP_ELOG(sp->log, RTPP_LOG_ERR, "can't open file %s for writing",
          rrc->spath);
        goto e2;
    }

    if (rrc->mode == MODE_LOCAL_PCAP) {
        pcap_hdr.magic_number = PCAP_MAGIC;
        pcap_hdr.version_major = PCAP_VER_MAJR;
        pcap_hdr.version_minor = PCAP_VER_MINR;
        pcap_hdr.thiszone = 0;
        pcap_hdr.sigfigs = 0;
        pcap_hdr.snaplen = 65535;
        pcap_hdr.network = PCAP_FORMAT;
        rval = write(rrc->fd, &pcap_hdr, sizeof(pcap_hdr));
        if (rval == -1) {
            RTPP_ELOG(sp->log, RTPP_LOG_ERR, "%s: error writing header",
              rrc->spath);
            goto e3;
        }
        if (rval < sizeof(pcap_hdr)) {
            RTPP_LOG(sp->log, RTPP_LOG_ERR, "%s: short write writing header",
              rrc->spath);
            goto e3;
        }
    }

    CALL_SMETHOD(rrc->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_record_close,
      rrc);
    return (&rrc->pub);

e3:
    if (rrc->mode != MODE_REMOTE_RTP)
        close(rrc->fd);
e2:
    RTPP_OBJ_DECREF(rrc->log);
    pthread_mutex_destroy(&rrc->lock);
e1:
    RTPP_OBJ_DECREF(&(rrc->pub));
e0:
    return NULL;
}

static int
flush_rbuf(struct rtpp_record_channel *rrc)
{
    int rval;

    rval = write(rrc->fd, rrc->rbuf, rrc->rbuf_len);
    if (rval != -1) {
        rrc->rbuf_len = 0;
        return 0;
    }

    RTPP_ELOG(rrc->log, RTPP_LOG_ERR, "error while recording session (%s)",
      rrc->proto);
    /* Prevent futher writing if error happens */
    if (rrc->mode != MODE_REMOTE_RTP)
        close(rrc->fd);
    rrc->fd = -1;
    return -1;
}

union anyhdr {
    union pkt_hdr_pcap pcap;
    struct pkt_hdr_adhoc adhoc;
};

struct prepare_pkt_hdr_args {
    const struct rtp_packet *packet;
    union anyhdr *hdrp;
    const struct sockaddr *daddr;
    const struct sockaddr *ldaddr;
    int ldport;
    int face;
    double atime_wall;
};

DEFINE_RAW_METHOD(prepare_pkt_hdr, int, const struct prepare_pkt_hdr_args *);

static int
prepare_pkt_hdr_adhoc(const struct prepare_pkt_hdr_args *phap)
{
    struct pkt_hdr_adhoc *ap;

    ap = &(phap->hdrp->adhoc);
    memset(ap, 0, sizeof(*ap));
    ap->time = phap->atime_wall;
    switch (sstosa(&phap->packet->raddr)->sa_family) {
    case AF_INET:
        ap->addr.in4.sin_family = sstosa(&phap->packet->raddr)->sa_family;
        ap->addr.in4.sin_port = satosin(&phap->packet->raddr)->sin_port;
        ap->addr.in4.sin_addr = satosin(&phap->packet->raddr)->sin_addr;
        break;

    case AF_INET6:
        ap->addr.in6.sin_family = sstosa(&phap->packet->raddr)->sa_family;
        ap->addr.in6.sin_port = satosin6(&phap->packet->raddr)->sin6_port;
        ap->addr.in6.sin_addr = satosin6(&phap->packet->raddr)->sin6_addr;
        break;

    default:
        abort();
    }

    ap->plen = phap->packet->size;
    return 0;
}

static uint16_t ip_id = 0;

#if (PCAP_FORMAT != DLT_NULL)
static void
fake_ether_addr(const struct sockaddr *addr, uint8_t *eaddr)
{
    uint8_t *ra;
    int i;

    switch (addr->sa_family) {
    case AF_INET:
        eaddr[0] = eaddr[1] = 0;
        memcpy(eaddr + 2, &(satosin(addr)->sin_addr), 4);
        return;

    case AF_INET6:
        ra = &satosin6(addr)->sin6_addr.s6_addr[0];
        memcpy(eaddr, ra, 6);
        for (i = 6; i < sizeof(struct in6_addr); i++) {
            eaddr[i % 6] ^= ra[i];
        }
        return;

    default:
        break;
    }
    abort();
}
#endif

static int
prepare_pkt_hdr_pcap(const struct prepare_pkt_hdr_args *phap)
{
    const struct sockaddr *src_addr, *dst_addr;
    uint16_t src_port, dst_port;
    pcaprec_hdr_t phd;
    union {
        struct ip6_hdr *v6;
        struct ip *v4;
    } ipp;
    struct udphdr *udp;
    int pcap_size;
    struct timeval rtimeval;
#if (PCAP_FORMAT != DLT_NULL)
    struct sockaddr_storage tmp_addr;
    struct layer2_hdr *ether;
#endif

    if (phap->face == 0) {
        src_addr = sstosa(&(phap->packet->raddr));
        src_port = getnport(src_addr);
        dst_addr = phap->packet->laddr;
        dst_port = htons(phap->packet->lport);
    } else {
        src_addr = phap->ldaddr;
        src_port = htons(phap->ldport);
        dst_addr = phap->daddr;
        dst_port = getnport(dst_addr);
    }

#if 0
    if (src_addr->sa_family != AF_INET) {
        RTPP_ELOG(phap->log, RTPP_LOG_ERR, "only AF_INET pcap format is supported");
        return -1;
    }
#endif

    union pkt_hdr_pcap *pcp = &(phap->hdrp->pcap);
    memset(pcp, 0, get_hdr_size(src_addr));
    memset(&phd, 0, sizeof(phd));

#if (PCAP_FORMAT == DLT_NULL)
    pcap_size = (src_addr->sa_family == AF_INET) ? sizeof(pcp->null) :
      sizeof(pcp->null_v6);
#else
    pcap_size = (src_addr->sa_family == AF_INET) ? sizeof(pcp->en10t) :
       sizeof(pcp->en10t_v6);
#endif

    dtime2timeval(phap->atime_wall, &rtimeval);

    RTPP_DBG_ASSERT(SEC(&rtimeval) > 0 && SEC(&rtimeval) <= UINT32_MAX);
    RTPP_DBG_ASSERT(USEC(&rtimeval) < USEC_MAX);

    phd.ts_sec = SEC(&rtimeval);
    phd.ts_usec = USEC(&rtimeval);
    phd.orig_len = phd.incl_len = pcap_size -
      sizeof(phd) + phap->packet->size;

#if (PCAP_FORMAT == DLT_NULL)
    if (src_addr->sa_family == AF_INET) {
        memcpy(&pcp->null.pcaprec_hdr, &phd, sizeof(phd));
        pcp->null.family = src_addr->sa_family;
        ipp.v4 = &(pcp->null.udpip.iphdr);
        udp = &(pcp->null.udpip.udphdr);
    } else {
        memcpy(&pcp->null_v6.pcaprec_hdr, &phd, sizeof(phd));
        pcp->null_v6.family = src_addr->sa_family;
        ipp.v6 = &(pcp->null_v6.udpip6.iphdr);
        udp = &(pcp->null_v6.udpip6.udphdr);
    }
#else
    /* Prepare fake ethernet header */
    if (src_addr->sa_family == AF_INET) {
        memcpy(&pcp->en10t.pcaprec_hdr, &phd, sizeof(phd));
        ether = &pcp->en10t.ether;
        ether->type = ETHERTYPE_INET;
        udp = &(pcp->en10t.udpip.udphdr);
        ipp.v4 = &(pcp->en10t.udpip.iphdr);
    } else {
        memcpy(&pcp->en10t_v6.pcaprec_hdr, &phd, sizeof(phd));
        ether = &pcp->en10t_v6.ether;
        ether->type = ETHERTYPE_INET6;
        udp = &(pcp->en10t_v6.udpip6.udphdr);
        ipp.v6 = &(pcp->en10t_v6.udpip6.iphdr);
    }
    if (phap->face == 0 && ishostnull(dst_addr) && !ishostnull(src_addr)) {
        if (local4remote(src_addr, &tmp_addr) == 0) {
            dst_addr = sstosa(&tmp_addr);
        } else {
            return -1;
        }
    }
    fake_ether_addr(dst_addr, ether->dhost);
    if (phap->face != 0 && ishostnull(src_addr) && !ishostnull(dst_addr)) {
        if (local4remote(dst_addr, &tmp_addr) == 0) {
            src_addr = sstosa(&tmp_addr);
        } else {
            return -1;
        }
    }
    fake_ether_addr(src_addr, ether->shost);
#endif

    /* Prepare fake IP header */
    if (src_addr->sa_family == AF_INET) {
        ipp.v4->ip_v = 4;
        ipp.v4->ip_hl = sizeof(*ipp.v4) >> 2;
        ipp.v4->ip_len = htons(sizeof(*ipp.v4) + sizeof(*udp) + phap->packet->size);
        ipp.v4->ip_src = satosin(src_addr)->sin_addr;
        ipp.v4->ip_dst = satosin(dst_addr)->sin_addr;
        ipp.v4->ip_p = IPPROTO_UDP;
        ipp.v4->ip_id = htons(ip_id++);
        ipp.v4->ip_ttl = 127;
        ipp.v4->ip_sum = rtpp_in_cksum(ipp.v4, sizeof(*ipp.v4));
    } else {
        ipp.v6->ip6_vfc |= IPV6_VERSION;
        ipp.v6->ip6_hlim = IPV6_DEFHLIM;
        ipp.v6->ip6_nxt = IPPROTO_UDP;
        ipp.v6->ip6_src = satosin6(src_addr)->sin6_addr;
        ipp.v6->ip6_dst = satosin6(dst_addr)->sin6_addr;
        ipp.v6->ip6_plen = htons(sizeof(*udp) + phap->packet->size);
    }

    /* Prepare fake UDP header */
    udp->uh_sport = src_port;
    udp->uh_dport = dst_port;
    udp->uh_ulen = htons(sizeof(*udp) + phap->packet->size);

    rtpp_ip_chksum_start();
    if (src_addr->sa_family == AF_INET) {
        rtpp_ip_chksum_update(&(ipp.v4->ip_src), sizeof(ipp.v4->ip_src));
        rtpp_ip_chksum_update(&(ipp.v4->ip_dst), sizeof(ipp.v4->ip_dst));
        rtpp_ip_chksum_pad_v4();
        rtpp_ip_chksum_update(&(udp->uh_ulen), sizeof(udp->uh_ulen));
    } else {
        uint32_t ulen32 = htonl(sizeof(*udp) + phap->packet->size);

        rtpp_ip_chksum_update(&ipp.v6->ip6_src, sizeof(ipp.v6->ip6_src));
        rtpp_ip_chksum_update(&ipp.v6->ip6_dst, sizeof(ipp.v6->ip6_dst));
        rtpp_ip_chksum_update(&ulen32, sizeof(ulen32));
        rtpp_ip_chksum_pad_v6();
    }
    rtpp_ip_chksum_update(&(udp->uh_sport), sizeof(udp->uh_sport));
    rtpp_ip_chksum_update(&(udp->uh_dport), sizeof(udp->uh_dport));
    rtpp_ip_chksum_update(&(udp->uh_ulen), sizeof(udp->uh_ulen));
    rtpp_ip_chksum_update_data(phap->packet->data.buf, phap->packet->size);
    rtpp_ip_chksum_fin(udp->uh_sum);

    return 0;
}

static int
get_hdr_size(const struct sockaddr *raddr)
{
    int hdr_size;

#if (PCAP_FORMAT == DLT_NULL)
    if (raddr->sa_family == AF_INET) {
        hdr_size = sizeof(struct pkt_hdr_pcap_null);
    } else {
        hdr_size = sizeof(struct pkt_hdr_pcap_null_v6);
    }
#else
    if (raddr->sa_family == AF_INET) {
        hdr_size = sizeof(struct pkt_hdr_pcap_en10t);
    } else {
        hdr_size = sizeof(struct pkt_hdr_pcap_en10t_v6);
    }
#endif
    return (hdr_size);
}

static void
rtpp_record_write_locked(struct rtpp_record_channel *rrc, const struct pkt_proc_ctx *pktxp)
{
    struct iovec v[2];
    int rval, hdr_size;
    prepare_pkt_hdr_t prepare_pkt_hdr;
    const char *proto;
    struct sockaddr_storage daddr;
    struct rtpp_netaddr *rem_addr;
    struct rtp_packet *packet = pktxp->pktp;
    struct rtpp_stream *stp = pktxp->strmp_out;

    if (rrc->fd == -1)
        return;

    rem_addr = CALL_SMETHOD(stp, get_rem_addr, 0);
    if (rem_addr != NULL) {
        CALL_SMETHOD(rem_addr, get, sstosa(&daddr), sizeof(daddr));
        RTPP_OBJ_DECREF(rem_addr);
    } else {
        memset(&daddr, 0, sizeof(daddr));
        sstosa(&daddr)->sa_family = stp->laddr->sa_family;
    }

    if (packet->rtime.wall == -1) {
        RTPP_ELOG(stp->log, RTPP_LOG_ERR, "can't get current time");
    }

    if (rrc->epoch.wall == 0) {
        rrc->epoch = packet->rtime;
    }

    switch (rrc->mode) {
    case MODE_REMOTE_RTP:
        send(rrc->fd, packet->data.buf, packet->size, 0);
        return;

    case MODE_LOCAL_PKT:
        hdr_size = sizeof(struct pkt_hdr_adhoc);
        prepare_pkt_hdr = &prepare_pkt_hdr_adhoc;
        break;

    case MODE_LOCAL_PCAP:
        hdr_size = get_hdr_size(sstosa(&packet->raddr));
        prepare_pkt_hdr = &prepare_pkt_hdr_pcap;
        break;

    default:
        /* Should not happen */
        abort();
    }

    /* Check if the write buffer has necessary space, and flush if not */
    if ((rrc->rbuf_len + hdr_size + packet->size > sizeof(rrc->rbuf)) && rrc->rbuf_len > 0)
        if (flush_rbuf(rrc) != 0)
            return;

    struct prepare_pkt_hdr_args pargs = {
      .packet = packet,
      .ldaddr = stp->laddr,
      .ldport = stp->port,
      .daddr = sstosa(&daddr),
      .face = (rrc->record_single_file == 0) ? 0 : (stp->pipe_type != PIPE_RTP),
      .atime_wall = ARRIVAL_TIME(rrc, packet)
    };

    /* Check if received packet doesn't fit into the buffer, do synchronous write  if so */
    if (rrc->rbuf_len + hdr_size + packet->size > sizeof(rrc->rbuf)) {
        union anyhdr hdr;
        pargs.hdrp = &hdr;

        if (prepare_pkt_hdr(&pargs) != 0)
            return;

        v[0].iov_base = (void *)&hdr;
        v[0].iov_len = hdr_size;
        v[1].iov_base = packet->data.buf;
        v[1].iov_len = packet->size;

        rval = writev(rrc->fd, v, 2);
        if (rval != -1)
            return;

        proto = CALL_SMETHOD(stp, get_proto);
        RTPP_ELOG(stp->log, RTPP_LOG_ERR, "error while recording session (%s)",
          proto);
        /* Prevent futher writing if error happens */
        if (rrc->mode != MODE_REMOTE_RTP)
            close(rrc->fd);
        rrc->fd = -1;
        return;
    }
    pargs.hdrp = (void *)rrc->rbuf + rrc->rbuf_len;
    if (prepare_pkt_hdr(&pargs) != 0)
        return;
    rrc->rbuf_len += hdr_size;
    memcpy(rrc->rbuf + rrc->rbuf_len, packet->data.buf, packet->size);
    rrc->rbuf_len += packet->size;
}

static void
rtpp_record_write(struct rtpp_record *self, const struct pkt_proc_ctx *pktxp)
{
    struct rtpp_record_channel *rrc;

    PUB2PVT(self, rrc);
    pthread_mutex_lock(&rrc->lock);
    rtpp_record_write_locked(rrc, pktxp);
    pthread_mutex_unlock(&rrc->lock);
}

static void
rtpp_record_close(struct rtpp_record_channel *rrc)
{
    static int keep = 1;

    rtpp_record_fin(&rrc->pub);
    if (rrc->mode != MODE_REMOTE_RTP && rrc->rbuf_len > 0)
        flush_rbuf(rrc);

    if (rrc->mode == MODE_REMOTE_RTP)
        goto done;

    if (rrc->fd != -1)
        close(rrc->fd);

    if (keep == 0) {
        if (unlink(rrc->spath) == -1)
            RTPP_ELOG(rrc->log, RTPP_LOG_ERR, "can't remove "
              "session record %s", rrc->spath);
    } else if (rrc->needspool == 1) {
        if (rename(rrc->spath, rrc->rpath) == -1)
            RTPP_ELOG(rrc->log, RTPP_LOG_ERR, "can't move "
              "session record from spool into permanent storage");
    }
done:
    RTPP_OBJ_DECREF(rrc->log);
    pthread_mutex_destroy(&rrc->lock);
}
