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
 * $Id$
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/queue.h>
#if defined(__FreeBSD__)
#include <sys/rtprio.h>
#else
#include <sys/resource.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sndfile.h>

#include "format_au.h"
#include "g711.h"
#include "decoder.h"
#include "session.h"
#include "../rtp.h"
#include "../rtp_analyze.h"

static int load_adhoc(unsigned char *, off_t, struct channels *,
  struct rtpp_session_stat *, enum origin);
static int load_pcap(unsigned char *, off_t, struct channels *,
  struct rtpp_session_stat *, enum origin);

static void
usage(void)
{

    fprintf(stderr, "usage: extractaudio [-ids] rdir outfile [link1] ... [linkN]\n");
    exit(1);
}

/* Lookup session given ssrc */
static struct session *
session_lookup(struct channels *channels, uint32_t ssrc)
{
    struct channel *cp;

    MYQ_FOREACH(cp, channels) {
        if (MYQ_FIRST(&(cp->session))->rpkt->ssrc == ssrc)
            return &(cp->session);
    }
    return NULL;
}

/* Insert channel keeping them ordered by time of first packet arrival */
static void
channel_insert(struct channels *channels, struct channel *channel)
{
    struct channel *cp;

    MYQ_FOREACH_REVERSE(cp, channels)
        if (MYQ_FIRST(&(cp->session))->pkt->time <
          MYQ_FIRST(&(channel->session))->pkt->time) {
            MYQ_INSERT_AFTER(channels, cp, channel);
            return;
        }
    MYQ_INSERT_HEAD(channels, channel);
}

static int
load_session(const char *path, struct channels *channels, enum origin origin)
{
    int ifd, pcount;
    unsigned char *ibuf;
    struct stat sb;
    struct rtpp_session_stat stat;

    memset(&stat, '\0', sizeof(stat));

    ifd = open(path, O_RDONLY);
    if (ifd == -1)
        return -1;
    if (fstat(ifd, &sb) == -1) {
        close(ifd);
        return -1;
    }
    if (sb.st_size == 0) {
        close(ifd);
        return 0;
    }
    ibuf = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, ifd, 0);
    if (ibuf == MAP_FAILED) {
        close(ifd);
        return -1;
    }

    if (*(uint32_t *)ibuf != PCAP_MAGIC) {
        pcount = load_adhoc(ibuf, sb.st_size, channels, &stat, origin);
    } else {
        pcount = load_pcap(ibuf, sb.st_size, channels, &stat, origin);
    }

    update_rtpp_totals(&stat);
    printf("pcount=%u, min_seq=%u, max_seq=%u, seq_offset=%u, ssrc=%u, duplicates=%u\n",
      (unsigned int)stat.last.pcount, (unsigned int)stat.last.min_seq, (unsigned int)stat.last.max_seq,
      (unsigned int)stat.last.seq_offset, (unsigned int)stat.last.ssrc, (unsigned int)stat.last.duplicates);
    printf("ssrc_changes=%u, psent=%u, precvd=%u\n", stat.ssrc_changes, stat.psent, stat.precvd);
    close(ifd);

    return pcount;
}

static int
load_adhoc(unsigned char *ibuf, off_t st_size, struct channels *channels,
  struct rtpp_session_stat *stat, enum origin origin)
{
    int pcount;
    unsigned char *cp;
    struct pkt_hdr_adhoc *pkt;
    struct packet *pack, *pp;
    struct channel *channel;
    struct session *sess;

    pcount = 0;
    for (cp = ibuf; cp < ibuf + st_size; cp += pkt->plen) {
        pkt = (struct pkt_hdr_adhoc *)cp;
        cp += sizeof(*pkt);
        if (pkt->plen < sizeof(rtp_hdr_t))
            continue;
        pack = malloc(sizeof(*pack));
        if (rtp_packet_parse(cp, pkt->plen, &(pack->parsed)) != RTP_PARSER_OK) {
            /* XXX error handling */
            free(pack);
            continue;
        }
        pack->pkt = pkt;
        pack->rpkt = RPKT(pack);
        update_rtpp_stats(stat, pack->rpkt, &(pack->parsed), pkt->time);

        sess = session_lookup(channels, pack->rpkt->ssrc);
        if (sess == NULL) {
            channel = malloc(sizeof(*channel));
            memset(channel, 0, sizeof(*channel));
            channel->origin = origin;
            sess = &(channel->session);
            MYQ_INIT(sess);
            MYQ_INSERT_HEAD(sess, pack);
            channel_insert(channels, channel);
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
                pcount++;
                goto endloop;
            }
        }
        MYQ_INSERT_HEAD(sess, pack);
        pcount++;
endloop:
        continue;
    }
    if (cp != ibuf + st_size) {
        warnx("invalid format, %d packets loaded", pcount);
        return -1;
    }
    return pcount;
}

static int
load_pcap(unsigned char *ibuf, off_t st_size, struct channels *channels,
  struct rtpp_session_stat *stat, enum origin origin)
{
    int pcount;
    unsigned char *cp;
    struct packet *pack, *pp;
    struct channel *channel;
    struct session *sess;
    pcap_hdr_t *pcap_hdr;
    struct pkt_hdr_pcap *pcap;
    int rtp_len;

    if (st_size < sizeof(*pcap_hdr)) {
        warnx("invalid PCAP format");
        return -1;
    }
    pcap_hdr = (pcap_hdr_t *)ibuf;
    ibuf += sizeof(*pcap_hdr);
    st_size -= sizeof(*pcap_hdr);
    pcount = 0;
    for (cp = ibuf; cp < ibuf + st_size; cp += rtp_len) {
        pcap = (struct pkt_hdr_pcap *)cp;
        rtp_len = pcap->pcaprec_hdr.incl_len - (sizeof(*pcap) - sizeof(pcap->pcaprec_hdr));
        if (rtp_len < 0) {
            warnx("broken or truncated PCAP file");
            return -1;
        }
        cp += sizeof(*pcap);
        if (rtp_len < sizeof(rtp_hdr_t))
            continue;
        pack = malloc(sizeof(*pack) + sizeof(*pack->pkt));
        if (rtp_packet_parse(cp, rtp_len, &(pack->parsed)) != RTP_PARSER_OK) {
            /* XXX error handling */
            free(pack);
            continue;
        }
        pack->pkt = (struct pkt_hdr_adhoc *)&pack[1];
        pack->rpkt = (rtp_hdr_t *)cp;
        pack->pkt->time = ts2dtime(pcap->pcaprec_hdr.ts_sec, pcap->pcaprec_hdr.ts_usec);
        pack->pkt->plen = rtp_len;
        if (origin == O_CH) {
            pack->pkt->addr.in4.sin_family = AF_INET;
            pack->pkt->addr.in4.sin_port = ntohs(pcap->udphdr.uh_dport);
            pack->pkt->addr.in4.sin_addr = pcap->iphdr.ip_dst;
        } else {
            pack->pkt->addr.in4.sin_family = AF_INET;
            pack->pkt->addr.in4.sin_port = ntohs(pcap->udphdr.uh_sport);
            pack->pkt->addr.in4.sin_addr = pcap->iphdr.ip_src;
        }
        update_rtpp_stats(stat, pack->rpkt, &(pack->parsed), pack->pkt->time);

        sess = session_lookup(channels, pack->rpkt->ssrc);
        if (sess == NULL) {
            channel = malloc(sizeof(*channel));
            memset(channel, 0, sizeof(*channel));
            channel->origin = origin;
            sess = &(channel->session);
            MYQ_INIT(sess);
            MYQ_INSERT_HEAD(sess, pack);
            channel_insert(channels, channel);
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
                pcount++;
                goto endloop;
            }
        }
        MYQ_INSERT_HEAD(sess, pack);
        pcount++;
endloop:
        continue;
    }
    if (cp != ibuf + st_size) {
        warnx("invalid format, %d packets loaded", pcount);
        return -1;
    }
    return pcount;
}

int
main(int argc, char **argv)
{
    int ch;
    int oblen, delete, stereo, idprio, nch, neof;
    int32_t osample, asample, csample;
    struct channels channels;
    struct channel *cp;
#if defined(__FreeBSD__)
    struct rtprio rt;
#endif
    int16_t obuf[1024];
    char aname[MAXPATHLEN], oname[MAXPATHLEN];
    double basetime;
    SF_INFO sfinfo;
    SNDFILE *sffile;

    MYQ_INIT(&channels);
    memset(&sfinfo, 0, sizeof(sfinfo));

    delete = stereo = idprio = 0;
    while ((ch = getopt(argc, argv, "dsi")) != -1)
        switch (ch) {
        case 'd':
            delete = 1;
            break;

        case 's':
            stereo = 1;
            break;

        case 'i':
            idprio = 1;
            break;

        case '?':
        default:
            usage();
        }
    argc -= optind;
    argv += optind;

    if (argc < 2)
        usage();

    if (idprio != 0) {
#if defined(__FreeBSD__)
        rt.type = RTP_PRIO_IDLE;
        rt.prio = RTP_PRIO_MAX;
        rtprio(RTP_SET, 0, &rt);
#else
        setpriority(PRIO_PROCESS, 0, 20);
#endif
    }

    sprintf(aname, "%s.a.rtp", argv[0]);
    sprintf(oname, "%s.o.rtp", argv[0]);

    load_session(aname, &channels, A_CH);
    load_session(oname, &channels, O_CH);

    if (MYQ_EMPTY(&channels))
        goto theend;

    nch = 0;
    basetime = MYQ_FIRST(&(MYQ_FIRST(&channels)->session))->pkt->time;
    MYQ_FOREACH(cp, &channels) {
        if (basetime > MYQ_FIRST(&(cp->session))->pkt->time)
            basetime = MYQ_FIRST(&(cp->session))->pkt->time;
    }
    MYQ_FOREACH(cp, &channels) {
        cp->skip = (MYQ_FIRST(&(cp->session))->pkt->time - basetime) * 8000;
        cp->decoder = decoder_new(&(cp->session));
        nch++;
    }

    oblen = 0;

    sfinfo.samplerate = 8000;
    if (stereo == 0) {
        sfinfo.channels = 1;
        sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_GSM610;
    } else {
        /* GSM+WAV doesn't work with more than 1 channels */
        sfinfo.channels = 2;
        sfinfo.format = SF_FORMAT_WAV | SF_FORMAT_MS_ADPCM;
    }

    sffile = sf_open(argv[1], SFM_WRITE, &sfinfo);
    if (sffile == NULL)
        errx(2, "%s: can't open output file", argv[1]);

    do {
        neof = 0;
        asample = osample = 0;
        MYQ_FOREACH(cp, &channels) {
            if (cp->skip > 0) {
                cp->skip--;
		continue;
            }
            csample = decoder_get(cp->decoder);
            if (csample == DECODER_EOF || csample == DECODER_ERROR) {
                neof++;
                continue;
            }
            if (cp->origin == A_CH)
                asample += csample;
            else
                osample += csample;
        }
        if (neof < nch) {
            if (stereo == 0) {
                obuf[oblen] = (asample + osample) / 2;
                oblen += 1;
            } else {
                obuf[oblen] = asample;
                oblen += 1;
                obuf[oblen] = osample;
                oblen += 1;
            }
        }
        if (neof == nch || oblen == sizeof(obuf) / sizeof(obuf[0])) {
            sf_write_short(sffile, obuf, oblen);
            oblen = 0;
        }
    } while (neof < nch);

    sf_close(sffile);

    while (argc > 2) {
        link(argv[1], argv[argc - 1]);
        argc--;
    }

theend:
    if (delete != 0) {
        unlink(aname);
        unlink(oname);
    }

    return 0;
}
