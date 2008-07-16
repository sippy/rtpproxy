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
#include <sys/rtprio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "format_au.h"
#include "decoder.h"
#include "session.h"
#include "../rtp.h"

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

    TAILQ_FOREACH(cp, channels, link) {
        if (RPKT(TAILQ_FIRST(&(cp->session)))->ssrc == ssrc)
            return &(cp->session);
    }
    return NULL;
}

/* Insert channel keeping them ordered by time of first packet arrival */
static void
channel_insert(struct channels *channels, struct channel *channel)
{
    struct channel *cp;

    TAILQ_FOREACH_REVERSE(cp, channels, channels, link)
        if (TAILQ_FIRST(&(cp->session))->pkt->time <
          TAILQ_FIRST(&(channel->session))->pkt->time) {
            TAILQ_INSERT_AFTER(channels, cp, channel, link);
            return;
        }
    TAILQ_INSERT_HEAD(channels, channel, link);
}

static int
load_session(const char *path, struct channels *channels, enum origin origin)
{
    int ifd, pcount, len;
    unsigned char *ibuf, *cp;
    struct stat sb;
    struct pkt_hdr_adhoc *pkt;
    struct packet *pack, *pp;
    rtp_hdr_t *rpkt;
    struct channel *channel;
    struct session *sess;

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
    ibuf = mmap(NULL, sb.st_size, PROT_READ, 0, ifd, 0);
    if (ibuf == MAP_FAILED) {
        close(ifd);
        return -1;
    }

    pcount = 0;
    for (cp = ibuf; cp < ibuf + sb.st_size; cp += pkt->plen) {
        pkt = (struct pkt_hdr_adhoc *)cp;
        if (pkt->plen < sizeof(*rpkt))
            break;
        cp += sizeof(*pkt);
        rpkt = (rtp_hdr_t *)cp;
        if (pkt->plen < RTP_HDR_LEN(rpkt) + ((rpkt->p != 0) ? 1 : 0))
            continue;
        len = pkt->plen - RTP_HDR_LEN(rpkt) - ((rpkt->p != 0) ? cp[pkt->plen - 1] : 0);
        if (len <= 0)
            continue;
        pack = malloc(sizeof(*pack));
        pack->pkt = pkt;
        pack->pload = cp + RTP_HDR_LEN(rpkt);
        pack->plen = len;

        sess = session_lookup(channels, RPKT(pack)->ssrc);
        if (sess == NULL) {
            channel = malloc(sizeof(*channel));
            memset(channel, 0, sizeof(*channel));
            channel->origin = origin;
            sess = &(channel->session);
            TAILQ_INIT(sess);
            TAILQ_INSERT_HEAD(sess, pack, link);
            channel_insert(channels, channel);
            pcount++;
            goto endloop;
        }

        /* Put packet it order */
        TAILQ_FOREACH_REVERSE(pp, sess, session, link) {
            if (ntohs(RPKT(pp)->seq) == ntohs(RPKT(pack)->seq)) {
                /* Duplicate packet */
                free(pack);
                goto endloop;
            }
            if (ntohs(RPKT(pp)->seq) < ntohs(RPKT(pack)->seq)) {
                TAILQ_INSERT_AFTER(sess, pp, pack, link);
                pcount++;
                goto endloop;
            }
        }
        TAILQ_INSERT_HEAD(sess, pack, link);
        pcount++;
endloop:
        continue;
    }
    close(ifd);
    if (cp != ibuf + sb.st_size) {
        warnx("%s: invalid format, %d packets loaded", path, pcount);
        return -1;
    }

    return pcount;
}

int
main(int argc, char **argv)
{
    int ch;
    int ofd, oblen, delete, stereo, idprio, nch, neof;
    int32_t osample, asample, csample;
    struct channels channels;
    struct channel *cp;
    struct filehdr_au filehdr_au;
    struct rtprio rt;
    int16_t obuf[1024];
    char aname[MAXPATHLEN], oname[MAXPATHLEN];
    double basetime;

    TAILQ_INIT(&channels);

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
        rt.type = RTP_PRIO_IDLE;
        rt.prio = RTP_PRIO_MAX;
        rtprio(RTP_SET, 0, &rt);
    }

    sprintf(aname, "%s.a.rtp", argv[0]);
    sprintf(oname, "%s.o.rtp", argv[0]);

    load_session(aname, &channels, A_CH);
    load_session(oname, &channels, O_CH);

    if (TAILQ_EMPTY(&channels))
        goto theend;

    nch = 0;
    basetime = TAILQ_FIRST(&(TAILQ_FIRST(&channels)->session))->pkt->time;
    TAILQ_FOREACH(cp, &channels, link) {
        if (basetime > TAILQ_FIRST(&(cp->session))->pkt->time)
            basetime = TAILQ_FIRST(&(cp->session))->pkt->time;
    }
    TAILQ_FOREACH(cp, &channels, link) {
        cp->skip = (TAILQ_FIRST(&(cp->session))->pkt->time - basetime) * 8000;
        cp->decoder = decoder_new(&(cp->session));
        nch++;
    }

    ofd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
    if (ofd == -1)
        err(2, "%s", argv[1]);

    lseek(ofd, sizeof(filehdr_au), SEEK_SET);
    memset(&filehdr_au, 0, sizeof(filehdr_au));
    oblen = 0;

    do {
        neof = 0;
        asample = osample = 0;
        TAILQ_FOREACH(cp, &channels, link) {
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
                obuf[oblen++] = htons((asample + osample) / 2);
            } else {
                obuf[oblen++] = htons(asample);
                obuf[oblen++] = htons(osample);
            }
        }

        if (neof == nch || oblen == (sizeof(obuf) / 2)) {
            write(ofd, obuf, oblen * 2);
            filehdr_au.data_size += oblen * 2;
            oblen = 0;
        }
    } while (neof < nch);

    filehdr_au.magic = htonl(AUDIO_FILE_MAGIC);
    filehdr_au.hdr_size = htonl(sizeof(filehdr_au));
    filehdr_au.data_size = htonl(filehdr_au.data_size);
    filehdr_au.encoding = htonl(AUDIO_FILE_ENCODING_LINEAR_16);
    filehdr_au.sample_rate = htonl(8000);
    if (stereo == 0)
        filehdr_au.channels = htonl(1);
    else
        filehdr_au.channels = htonl(2);
    lseek(ofd, 0, SEEK_SET);
    write(ofd, &filehdr_au, sizeof(filehdr_au));

    close(ofd);

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
