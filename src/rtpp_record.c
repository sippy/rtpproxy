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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_ip_chksum.h"
#include "rtpp_debug.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_mallocs.h"
#include "rtpp_monotime.h"
#include "rtpp_network.h"
#include "rtpp_record.h"
#include "rtpp_record_fin.h"
#include "rtpp_record_private.h"
#include "rtpp_session.h"
#include "rtpp_stream.h"
#include "rtpp_time.h"
#include "rtpp_pipe.h"
#include "rtpp_netaddr.h"

enum record_mode {MODE_LOCAL_PKT, MODE_REMOTE_RTP, MODE_LOCAL_PCAP}; /* MODE_LOCAL_RTP/MODE_REMOTE_PKT? */

struct rtpp_record_channel {
    struct rtpp_record pub;
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
};

static void rtpp_record_write(struct rtpp_record *, struct rtpp_stream *, struct rtp_packet *);
static void rtpp_record_close(struct rtpp_record_channel *);
static int get_hdr_size(const struct sockaddr *);

#define PUB2PVT(pubp) \
  ((struct rtpp_record_channel *)((char *)(pubp) - offsetof(struct rtpp_record_channel, pub)))

static int
ropen_remote_ctor_pa(struct rtpp_record_channel *rrc, struct rtpp_log *log,
  char *rname, int is_rtcp)
{
    char *cp, *tmp;
    int n, port;
    struct sockaddr_storage raddr;

    tmp = strdup(rname + 4);
    if (tmp == NULL) {
        RTPP_ELOG(log, RTPP_LOG_ERR, "can't allocate memory");
        goto e0;
    }
    rrc->mode = MODE_REMOTE_RTP;
    rrc->needspool = 0;
    cp = strrchr(tmp, ':');
    if (cp == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "remote recording target specification should include port number");
        goto e1;
    }
    *cp = '\0';
    cp++;

    if (is_rtcp) {
        /* Handle RTCP (increase target port by 1) */
        port = atoi(cp);
        if (port <= 0 || port > 65534) {
            RTPP_LOG(log, RTPP_LOG_ERR, "invalid port in the remote recording target specification");
            goto e1;
        }
        sprintf(cp, "%d", port + 1);
    }

    n = resolve(sstosa(&raddr), AF_INET, tmp, cp, AI_PASSIVE);
    if (n != 0) {
        RTPP_LOG(log, RTPP_LOG_ERR, "ropen: getaddrinfo: %s", gai_strerror(n));
        goto e1;
    }
    rrc->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rrc->fd == -1) {
        RTPP_ELOG(log, RTPP_LOG_ERR, "ropen: can't create socket");
        goto e1;
    }
    if (connect(rrc->fd, sstosa(&raddr), SA_LEN(sstosa(&raddr))) == -1) {
        RTPP_ELOG(log, RTPP_LOG_ERR, "ropen: can't connect socket");
        goto e2;
    }
    free(tmp);
    return (0);

e2:
    close(rrc->fd);
e1:
    free(tmp);
e0:
    return (-1);
}

struct rtpp_record *
rtpp_record_open(struct cfg *cf, struct rtpp_session *sp, char *rname, int orig,
  int record_type)
{
    struct rtpp_record_channel *rrc;
    struct rtpp_refcnt *rcnt;
    const char *sdir, *suffix1, *suffix2;
    int rval, remote;
    pcap_hdr_t pcap_hdr;

    remote = (rname != NULL && strncmp("udp:", rname, 4) == 0) ? 1 : 0;

    rrc = rtpp_rzmalloc(sizeof(*rrc), &rcnt);
    if (rrc == NULL) {
	RTPP_ELOG(sp->log, RTPP_LOG_ERR, "can't allocate memory");
	goto e0;
    }
    rrc->pub.rcnt = rcnt;

    rrc->record_single_file = (record_type == RECORD_BOTH) ? 1 : 0;
    if (rrc->record_single_file != 0) {
        rrc->proto = "RTP/RTCP";
    } else {
        rrc->proto = (record_type == RECORD_RTP) ? "RTP" : "RTCP";
    }
    rrc->log = sp->log;
    CALL_SMETHOD(sp->log->rcnt, incref);
    rrc->pub.write = &rtpp_record_write;
    if (remote) {
	rval = ropen_remote_ctor_pa(rrc, sp->log, rname, (record_type == RECORD_RTCP));
        if (rval < 0) {
            goto e2;
        }
        CALL_SMETHOD(rrc->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_record_close,
          rrc);
        return (&rrc->pub);
    }

    if (cf->stable->rdir == NULL) {
	RTPP_LOG(sp->log, RTPP_LOG_ERR, "directory for saving local recordings is not configured");
        goto e2;
    }

    if (cf->stable->record_pcap != 0) {
	rrc->mode = MODE_LOCAL_PCAP;
    } else {
	rrc->mode = MODE_LOCAL_PKT;
    }

    if (rrc->record_single_file != 0) {
        suffix1 = suffix2 = "";
    } else {
        suffix1 = (orig != 0) ? ".o" : ".a";
        suffix2 = (record_type == RECORD_RTP) ? ".rtp" : ".rtcp";
    }
    if (cf->stable->sdir == NULL) {
	sdir = cf->stable->rdir;
	rrc->needspool = 0;
    } else {
	sdir = cf->stable->sdir;
	rrc->needspool = 1;
	if (rname == NULL) {
	    sprintf(rrc->rpath, "%s/%s=%s%s%s", cf->stable->rdir, sp->call_id, sp->tag_nomedianum,
	      suffix1, suffix2);
	} else {
	    sprintf(rrc->rpath, "%s/%s%s", cf->stable->rdir, rname, suffix2);
	}
    }
    if (rname == NULL) {
	sprintf(rrc->spath, "%s/%s=%s%s%s", sdir, sp->call_id, sp->tag_nomedianum,
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
    close(rrc->fd);
e2:
    CALL_SMETHOD(rrc->log->rcnt, decref);
    CALL_SMETHOD(rrc->pub.rcnt, decref);
    free(rrc);
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
    close(rrc->fd);
    rrc->fd = -1;
    return -1;
}

static int
prepare_pkt_hdr_adhoc(struct rtpp_log *log, struct rtp_packet *packet,
  struct pkt_hdr_adhoc *hdrp, const struct sockaddr *daddr, struct sockaddr *ldaddr,
  int ldport, int face)
{

    memset(hdrp, 0, sizeof(*hdrp));
    hdrp->time = packet->rtime;
    if (hdrp->time == -1) {
	RTPP_ELOG(log, RTPP_LOG_ERR, "can't get current time");
	return -1;
    }
    switch (sstosa(&packet->raddr)->sa_family) {
    case AF_INET:
	hdrp->addr.in4.sin_family = sstosa(&packet->raddr)->sa_family;
	hdrp->addr.in4.sin_port = satosin(&packet->raddr)->sin_port;
	hdrp->addr.in4.sin_addr = satosin(&packet->raddr)->sin_addr;
	break;

    case AF_INET6:
	hdrp->addr.in6.sin_family = sstosa(&packet->raddr)->sa_family;
	hdrp->addr.in6.sin_port = satosin6(&packet->raddr)->sin6_port;
	hdrp->addr.in6.sin_addr = satosin6(&packet->raddr)->sin6_addr;
	break;

    default:
	abort();
    }

    hdrp->plen = packet->size;
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
prepare_pkt_hdr_pcap(struct rtpp_log *log, struct rtp_packet *packet,
  union pkt_hdr_pcap *hdrp, const struct sockaddr *daddr, struct sockaddr *ldaddr,
  int ldport, int face)
{
    const struct sockaddr *src_addr, *dst_addr;
    uint16_t src_port, dst_port;
    pcaprec_hdr_t *php;
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

    if (packet->rtime == -1) {
	RTPP_ELOG(log, RTPP_LOG_ERR, "can't get current time");
	return -1;
    }

    if (face == 0) {
        src_addr = sstosa(&(packet->raddr));
        src_port = getnport(src_addr);
        dst_addr = packet->laddr;
        dst_port = htons(packet->lport);
    } else {
        src_addr = ldaddr;
        src_port = htons(ldport);
        dst_addr = daddr;
        dst_port = getnport(dst_addr);
    }

#if 0
    if (src_addr->sa_family != AF_INET) {
	RTPP_ELOG(log, RTPP_LOG_ERR, "only AF_INET pcap format is supported");
	return -1;
    }
#endif

    memset(hdrp, 0, get_hdr_size(src_addr));

#if (PCAP_FORMAT == DLT_NULL)
    if (src_addr->sa_family == AF_INET) {
        php = &hdrp->null.pcaprec_hdr;
        hdrp->null.family = src_addr->sa_family;
        ipp.v4 = &(hdrp->null.udpip.iphdr);
        udp = &(hdrp->null.udpip.udphdr);
        pcap_size = sizeof(hdrp->null);
    } else {
        php = &hdrp->null_v6.pcaprec_hdr;
        hdrp->null_v6.family = src_addr->sa_family;
        ipp.v6 = &(hdrp->null_v6.udpip6.iphdr);
        udp = &(hdrp->null_v6.udpip6.udphdr);
        pcap_size = sizeof(hdrp->null_v6);
    }
#else
    /* Prepare fake ethernet header */
    if (src_addr->sa_family == AF_INET) {
        php = &hdrp->en10t.pcaprec_hdr;
        ether = &hdrp->en10t.ether;
        ether->type = ETHERTYPE_INET;
        udp = &(hdrp->en10t.udpip.udphdr);
        pcap_size = sizeof(hdrp->en10t);
        ipp.v4 = &(hdrp->en10t.udpip.iphdr);
    } else {
        php = &hdrp->en10t_v6.pcaprec_hdr;
        ether = &hdrp->en10t_v6.ether;
        ether->type = ETHERTYPE_INET6;
        udp = &(hdrp->en10t_v6.udpip6.udphdr);
        pcap_size = sizeof(hdrp->en10t_v6);
        ipp.v6 = &(hdrp->en10t_v6.udpip6.iphdr);
    }
    if (face == 0 && ishostnull(dst_addr) && !ishostnull(src_addr)) {
        if (local4remote(src_addr, &tmp_addr) == 0) {
            dst_addr = sstosa(&tmp_addr);
        }
    }
    fake_ether_addr(dst_addr, ether->dhost);
    if (face != 0 && ishostnull(src_addr) && !ishostnull(dst_addr)) {
        if (local4remote(dst_addr, &tmp_addr) == 0) {
            src_addr = sstosa(&tmp_addr);
        }
    }
    fake_ether_addr(src_addr, ether->shost);
#endif

    dtime2rtimeval(packet->rtime, &rtimeval);
    php->ts_sec = SEC(&rtimeval);
    php->ts_usec = USEC(&rtimeval);
    php->orig_len = php->incl_len = pcap_size -
      sizeof(*php) + packet->size;

    /* Prepare fake IP header */
    if (src_addr->sa_family == AF_INET) {
        ipp.v4->ip_v = 4;
        ipp.v4->ip_hl = sizeof(*ipp.v4) >> 2;
        ipp.v4->ip_len = htons(sizeof(*ipp.v4) + sizeof(*udp) + packet->size);
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
        ipp.v6->ip6_plen = htons(sizeof(*udp) + packet->size);
    }

    /* Prepare fake UDP header */
    udp->uh_sport = src_port;
    udp->uh_dport = dst_port;
    udp->uh_ulen = htons(sizeof(*udp) + packet->size);

    rtpp_ip_chksum_start();
    if (src_addr->sa_family == AF_INET) {
        rtpp_ip_chksum_update(&(ipp.v4->ip_src), sizeof(ipp.v4->ip_src));
        rtpp_ip_chksum_update(&(ipp.v4->ip_dst), sizeof(ipp.v4->ip_dst));
        rtpp_ip_chksum_pad_v4();
        rtpp_ip_chksum_update(&(udp->uh_ulen), sizeof(udp->uh_ulen));
    } else {
        uint32_t ulen32;

        rtpp_ip_chksum_update(&ipp.v6->ip6_src, sizeof(ipp.v6->ip6_src));
        rtpp_ip_chksum_update(&ipp.v6->ip6_dst, sizeof(ipp.v6->ip6_dst));
        ulen32 = htonl(sizeof(*udp) + packet->size);
        rtpp_ip_chksum_update(&ulen32, sizeof(ulen32));
        rtpp_ip_chksum_pad_v6();
    }
    rtpp_ip_chksum_update(&(udp->uh_sport), sizeof(udp->uh_sport));
    rtpp_ip_chksum_update(&(udp->uh_dport), sizeof(udp->uh_dport));
    rtpp_ip_chksum_update(&(udp->uh_ulen), sizeof(udp->uh_ulen));
    rtpp_ip_chksum_update_data(packet->data.buf, packet->size);
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
rtpp_record_write(struct rtpp_record *self, struct rtpp_stream *stp, struct rtp_packet *packet)
{
    struct iovec v[2];
    union {
	union pkt_hdr_pcap pcap;
	struct pkt_hdr_adhoc adhoc;
    } hdr;
    int rval, hdr_size;
    int (*prepare_pkt_hdr)(struct rtpp_log *, struct rtp_packet *, void *,
      const struct sockaddr *, struct sockaddr *, int, int);
    const char *proto;
    struct sockaddr_storage daddr;
    struct sockaddr *ldaddr;
    int ldport, face;
    struct rtpp_record_channel *rrc;
    struct rtpp_netaddr *rem_addr;
    size_t dalen;

    rrc = PUB2PVT(self);

    if (rrc->fd == -1)
	return;

    rem_addr = CALL_SMETHOD(stp, get_rem_addr, 0);
    if (rem_addr == NULL) {
        return;
    }
    dalen = CALL_SMETHOD(rem_addr, get, sstosa(&daddr), sizeof(daddr));
    CALL_SMETHOD(rem_addr->rcnt, decref);
    ldaddr = stp->laddr;
    ldport = stp->port;

    switch (rrc->mode) {
    case MODE_REMOTE_RTP:
	send(rrc->fd, packet->data.buf, packet->size, 0);
	return;

    case MODE_LOCAL_PKT:
	hdr_size = sizeof(hdr.adhoc);
	prepare_pkt_hdr = (void *)&prepare_pkt_hdr_adhoc;
	break;

    case MODE_LOCAL_PCAP:
        hdr_size = get_hdr_size(sstosa(&packet->raddr));
	prepare_pkt_hdr = (void *)&prepare_pkt_hdr_pcap;
	break;

    default:
        /* Should not happen */
        abort();
    }

    /* Check if the write buffer has necessary space, and flush if not */
    if ((rrc->rbuf_len + hdr_size + packet->size > sizeof(rrc->rbuf)) && rrc->rbuf_len > 0)
	if (flush_rbuf(rrc) != 0)
	    return;

    face = (rrc->record_single_file == 0) ? 0 : (stp->pipe_type != PIPE_RTP);

    /* Check if received packet doesn't fit into the buffer, do synchronous write  if so */
    if (rrc->rbuf_len + hdr_size + packet->size > sizeof(rrc->rbuf)) {
	if (prepare_pkt_hdr(stp->log, packet, (void *)&hdr, sstosa(&daddr), ldaddr, ldport, face) != 0)
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
	close(rrc->fd);
	rrc->fd = -1;
	return;
    }
    if (prepare_pkt_hdr(stp->log, packet, (void *)rrc->rbuf + rrc->rbuf_len,
      sstosa(&daddr), ldaddr, ldport, face) != 0)
	return;
    rrc->rbuf_len += hdr_size;
    memcpy(rrc->rbuf + rrc->rbuf_len, packet->data.buf, packet->size);
    rrc->rbuf_len += packet->size;
}

static void
rtpp_record_close(struct rtpp_record_channel *rrc)
{
    static int keep = 1;

    rtpp_record_fin(&rrc->pub);
    if (rrc->mode != MODE_REMOTE_RTP && rrc->rbuf_len > 0)
	flush_rbuf(rrc);

    if (rrc->fd != -1)
	close(rrc->fd);

    if (rrc->mode == MODE_REMOTE_RTP)
	goto done;

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
    CALL_SMETHOD(rrc->log->rcnt, decref);

    free(rrc);
}
