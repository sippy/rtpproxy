/*
 * Copyright (c) 2007-2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#if HAVE_ERR_H
# include <err.h>
#endif

#include "rtpp_ssrc.h"
#include "rtp_info.h"
#include "rtpp_record_private.h"
#include "session.h"
#include "rtp_analyze.h"
#include "rtpp_loader.h"
#include "rtpp_time.h"
#include "rtpp_util.h"
#if ENABLE_SRTP || ENABLE_SRTP2
#include "eaud_crypto.h"
#endif
#include "eaud_pcap.h"

static int load_adhoc(struct rtpp_loader *loader, struct channels *,
  struct rtpp_session_stat *, enum origin, struct eaud_crypto *);
static int load_pcap(struct rtpp_loader *loader, struct channels *,
  struct rtpp_session_stat *, enum origin, struct eaud_crypto *);

static void
rtpp_loader_destroy(struct rtpp_loader *loader)
{

    close(loader->ifd);
    free(loader);
}

struct rtpp_loader *
rtpp_load(const char *path)
{
    struct rtpp_loader *rval;
    pcap_hdr_t *pcap_hdr;

    rval = malloc(sizeof(*rval));
    if (rval == NULL)
        return NULL;

    memset(rval, '\0', sizeof(*rval));

    rval->ifd = open(path, O_RDONLY);
    if (rval->ifd == -1) {
        free(rval);
        return NULL;
    }

    if (fstat(rval->ifd, &(rval->sb)) == -1 || rval->sb.st_size == 0) {
        close(rval->ifd);
        free(rval);
        return NULL;
    }

#if !ENABLE_SRTP && !ENABLE_SRTP2
    rval->ibuf = mmap(NULL, rval->sb.st_size, PROT_READ, MAP_SHARED,
      rval->ifd, 0);
#else
    /* Decryption is done in place, which is why PROT_WRITE */
    rval->ibuf = mmap(NULL, rval->sb.st_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE, rval->ifd, 0);
#endif
    if (rval->ibuf == MAP_FAILED) {
        close(rval->ifd);
        free(rval);
        return NULL;
    }

    rval->destroy = rtpp_loader_destroy;

    if (*(uint32_t *)(rval->ibuf) != PCAP_MAGIC) {
        rval->load = load_adhoc;
    } else {
        rval->load = load_pcap;
        if (rval->sb.st_size < sizeof(*pcap_hdr)) {
            warnx("invalid PCAP format");
            rval->destroy(rval);
            return NULL;
        }
        pcap_hdr = (pcap_hdr_t *)rval->ibuf;
        if (pcap_hdr->network != DLT_EN10MB && pcap_hdr->network != DLT_NULL) {
            warnx("unsupported data-link type in the PCAP: %d", pcap_hdr->network);
            rval->destroy(rval);
            return NULL;
        }
        if (pcap_hdr->version_major != PCAP_VER_MAJR || pcap_hdr->version_minor != PCAP_VER_MINR) {
            warnx("unsupported version of the PCAP: %d.%d", pcap_hdr->version_major, pcap_hdr->version_minor);
            rval->destroy(rval);
            return NULL;
        }

        rval->private.pcap_data.pcap_hdr = pcap_hdr;
        rval->ibuf += sizeof(*pcap_hdr);
        rval->sb.st_size -= sizeof(*pcap_hdr);
    }
    return rval;
}

static struct channel *
channel_alloc(enum origin origin)
{
    struct channel *channel;

    channel = malloc(sizeof(*channel));
    if (channel == NULL)
        return (NULL);
    memset(channel, 0, sizeof(*channel));
    channel->origin = origin;
    return (channel);
}

static int
load_adhoc(struct rtpp_loader *loader, struct channels *channels,
  struct rtpp_session_stat *stat, enum origin origin,
  struct eaud_crypto *crypto)
{
    int pcount, rcode;
    unsigned char *cp, *ep;
    struct pkt_hdr_adhoc *pkt;
    struct packet *pack, *pp;
    struct channel *channel;
    struct session *sess;
    off_t st_size;

    pcount = 0;
    st_size = loader->sb.st_size;
    ep = loader->ibuf + st_size;
    for (cp = loader->ibuf; cp < ep; cp += pkt->plen) {
        pkt = (struct pkt_hdr_adhoc *)cp;
        cp += sizeof(*pkt);
        if (pkt->plen < sizeof(rtp_hdr_t))
            continue;
        if (cp + pkt->plen > ep) {
            warnx("input file truncated, %ld bytes are missing",
              (long)(cp + pkt->plen - ep));
            continue;
        }
        pack = malloc(sizeof(*pack));
        if (pack == NULL) {
            warn("malloc() failed");
            return -1;
        }
        rcode = rtp_packet_parse_raw(cp, pkt->plen, &(pack->parsed));
        if (rcode != RTP_PARSER_OK) {
            /* XXX error handling */
            warnx("rtp_packet_parse_raw() failed: %s", rtp_packet_parse_errstr(rcode));
            free(pack);
            continue;
        }
        pack->pkt = pkt;
        pack->rpkt = RPKT(pack);
        if (update_rtpp_stats(NULL, stat, pack->rpkt, &(pack->parsed), pkt->time) == UPDATE_ERR) {
            /* XXX error handling */
            abort();
        }
        if (pack->parsed.nsamples <= 0) {
            warnx("pack->parsed.nsamples = %d", pack->parsed.nsamples);
            free(pack);
            continue;
        }

        sess = session_lookup(channels, pack->rpkt->ssrc, &channel);
        if (sess == NULL) {
            channel = channel_alloc(origin);
            if (channel == NULL) {
                goto e0;
            }
            sess = &(channel->session);
            MYQ_INIT(sess);
            MYQ_INSERT_HEAD(sess, pack);
            if (channel_insert(channels, channel) < 0) {
                warn("channel_insert() failed");
                goto e0;
            }
            pcount++;
            goto endloop;
        }

        /* Put packet it order */
        MYQ_FOREACH_REVERSE(pp, sess) {
            if (pp->parsed.seq == pack->parsed.seq) {
                /* Duplicate packet */
                free(pack);
                goto endloop;
            }
            if (pp->parsed.ts < pack->parsed.ts ||
              pp->parsed.seq < pack->parsed.seq) {
                MYQ_INSERT_AFTER(sess, pp, pack);
                goto reg_pack;
            }
        }
        MYQ_INSERT_HEAD(sess, pack);
reg_pack:
        pcount++;
endloop:
        continue;
    }
    if (cp != ep) {
        warnx("invalid format, %d packets loaded", pcount);
        return -1;
    }
    return pcount;
e0:
    free(pack);
    return (-1);
}

static int
load_pcap(struct rtpp_loader *loader, struct channels *channels,
  struct rtpp_session_stat *stat, enum origin origin,
  struct eaud_crypto *crypto)
{
    int pcount, rcode;
    unsigned char *cp, *ep;
    struct packet *pack, *pp;
    struct channel *channel;
    struct session *sess;
    int rtp_pkt_len, rval;
    off_t st_size;
    int network;
    struct pcap_dissect pd;

    st_size = loader->sb.st_size;
    network = loader->private.pcap_data.pcap_hdr->network;
    ep = loader->ibuf + st_size;

    pcount = 0;
    for (cp = loader->ibuf; cp < ep; cp += PCAP_REC_LEN(&pd)) {
        rval = eaud_pcap_dissect(cp, ep - cp, network, &pd);
        if (rval < 0) {
            if (rval == PCP_DSCT_UNKN)
                continue;
            warnx("broken or truncated PCAP file");
            return -1;
        }
        if (pd.l5_len < sizeof(rtp_hdr_t))
            continue;

#if ENABLE_SRTP || ENABLE_SRTP2
        if (crypto != NULL) {
            rtp_pkt_len = eaud_crypto_decrypt(crypto, pd.l5_data, pd.l5_len);
            if (rtp_pkt_len <= 0) {
                warnx("decryption failed");
                continue;
            }
            assert(rtp_pkt_len <= pd.l5_len);
        } else {
            rtp_pkt_len = pd.l5_len;
        }
#else
        rtp_pkt_len = pd.l5_len;
#endif

        pack = malloc(sizeof(*pack) + sizeof(*pack->pkt));
        if (pack == NULL) {
            warn("malloc() failed");
            return -1;
        }
        rcode = rtp_packet_parse_raw(pd.l5_data, rtp_pkt_len, &(pack->parsed));
        if (rcode != RTP_PARSER_OK) {
            /* XXX error handling */
            warnx("rtp_packet_parse_raw() failed: %s", rtp_packet_parse_errstr(rcode));
            free(pack);
            continue;
        }
        pack->pkt = (struct pkt_hdr_adhoc *)&pack[1];
        pack->rpkt = (rtp_hdr_t *)pd.l5_data;
        pack->pkt->time = ts2dtime(pd.pcaprec_hdr.ts_sec, pd.pcaprec_hdr.ts_usec);
        pack->pkt->plen = rtp_pkt_len;
        pack->pkt->addr.in4.sin_family = AF_INET;
        if (origin == B_CH) {
            pack->pkt->addr.in4.sin_port = pd.dport;
            memcpy(&pack->pkt->addr.in4.sin_addr, pd.dst,
              sizeof(pack->pkt->addr.in4.sin_addr));
        } else {
            pack->pkt->addr.in4.sin_port = pd.sport;
            memcpy(&pack->pkt->addr.in4.sin_addr, pd.src,
              sizeof(pack->pkt->addr.in4.sin_addr));
        }
        if (update_rtpp_stats(NULL, stat, pack->rpkt, &(pack->parsed), pack->pkt->time) == UPDATE_ERR) {
            /* XXX error handling */
            abort();
        }
        if (pack->parsed.nsamples <= 0) {
            warnx("pack->parsed.nsamples = %d", pack->parsed.nsamples);
            free(pack);
            continue;
        }

        sess = session_lookup(channels, pack->rpkt->ssrc, &channel);
        if (sess == NULL) {
            channel = channel_alloc(origin);
            if (channel == NULL) {
                warn("channel_alloc() failed");
                goto e0;
            }
            sess = &(channel->session);
            MYQ_INIT(sess);
            MYQ_INSERT_HEAD(sess, pack);
            if (channel_insert(channels, channel) < 0) {
                warn("channel_insert() failed");
                goto e0;
            }
            pcount++;
            goto endloop;
        }

        /* Put packet it order */
        MYQ_FOREACH_REVERSE(pp, sess) {
            if (pp->parsed.seq == pack->parsed.seq) {
                /* Duplicate packet */
                free(pack);
                goto endloop;
            }
            if (pp->parsed.ts < pack->parsed.ts ||
              pp->parsed.seq < pack->parsed.seq) {
                MYQ_INSERT_AFTER(sess, pp, pack);
                goto reg_pack;
            }
        }
        MYQ_INSERT_HEAD(sess, pack);
reg_pack:
        pcount++;
endloop:
        continue;
    }
    if (cp != loader->ibuf + st_size) {
        warnx("invalid format, %d packets loaded", pcount);
        return -1;
    }
    return pcount;
e0:
    free(pack);
    return (-1);
}
