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
#if defined(__FreeBSD__)
#include <sys/rtprio.h>
#else
#include <sys/resource.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <getopt.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sndfile.h>

#include "config.h"

#include "format_au.h"
#include "g711.h"
#include "rtp_info.h"
#include "decoder.h"
#include "session.h"
#include "rtpp_record_private.h"
#include "rtpp_ssrc.h"
#include "rtpp_loader.h"
#include "rtp.h"
#include "rtp_analyze.h"
#include "rtpa_stats.h"
#include "eaud_oformats.h"
#if ENABLE_SRTP || ENABLE_SRTP2
# include "eaud_crypto.h"
#endif

/*#define EAUD_DUMPRAW "/tmp/eaud.raw"*/

#if ENABLE_SRTP || ENABLE_SRTP2
#define LOPT_ALICE_CRYPTO 256
#define LOPT_BOB_CRYPTO   257
#endif

const static struct option longopts[] = {
#if ENABLE_SRTP || ENABLE_SRTP2
    { "alice-crypto", required_argument, NULL, LOPT_ALICE_CRYPTO },
    { "bob-crypto",   required_argument, NULL, LOPT_BOB_CRYPTO },
#endif
    { NULL,           0,                 NULL, 0 }
};

static void
usage(void)
{

    fprintf(stderr, "usage: extractaudio [-idsn] [-F file_fmt] [-D data_fmt] "
      "rdir outfile [link1] ... [linkN]\n");
    exit(1);
}

/* Lookup session given ssrc */
struct session *
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
void
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
load_session(const char *path, struct channels *channels, enum origin origin,
  struct eaud_crypto *crypto)
{
    int pcount, jc;
    struct rtpp_session_stat stat;
    struct rtpa_stats_jitter jstat;
    struct rtpp_loader *loader;

    loader = rtpp_load(path);
    if (loader == NULL)
        return -1;

    rtpp_stats_init(&stat);
    pcount = loader->load(loader, channels, &stat, origin, crypto);

    update_rtpp_totals(&stat, &stat);
    jc = get_jitter_stats(stat.jdata, &jstat);
    printf("pcount=%u, min_seq=%u, max_seq=%u, seq_offset=%u, ssrc=0x%.8X, duplicates=%u\n",
      (unsigned int)stat.last.pcount, (unsigned int)stat.last.min_seq, (unsigned int)stat.last.max_seq,
      (unsigned int)stat.last.seq_offset, (unsigned int)stat.last.ssrc.val, (unsigned int)stat.last.duplicates);
    printf("ssrc_changes=%u, psent=%u, precvd=%u, plost=%d\n", stat.ssrc_changes, stat.psent, stat.precvd,
      stat.psent - stat.precvd);
    if (jc > 0) {
        printf("last_jitter=%f,average_jitter=%f,max_jitter=%f\n",
          jstat.jlast, jstat.javg, jstat.jmax);
    }

    loader->destroy(loader);
    rtpp_stats_destroy(&stat);

    return pcount;
}

int
main(int argc, char **argv)
{
    int ch, seen_a, seen_o;
    int oblen, delete, stereo, idprio, nch, neof;
    int32_t osample, asample, csample;
    uint64_t nasamples, nosamples, nwsamples;
    struct channels channels;
    struct channel *cp;
#if defined(__FreeBSD__)
    struct rtprio rt;
#endif
    int16_t obuf[1024];
    char aname_s[MAXPATHLEN], oname_s[MAXPATHLEN];
    const char *aname, *oname;
    double basetime;
    SF_INFO sfinfo;
    SNDFILE *sffile;
    int dflags;
    const struct supported_fmt *sf_of;
    uint32_t use_file_fmt, use_data_fmt;
    uint32_t dflt_file_fmt, dflt_data_fmt;
    int option_index;
    struct eaud_crypto *alice_crypto, *bob_crypto;

    MYQ_INIT(&channels);
    memset(&sfinfo, 0, sizeof(sfinfo));
    sfinfo.samplerate = 8000;
    sfinfo.channels = 1;
    use_file_fmt = use_data_fmt = 0;
    dflt_file_fmt = SF_FORMAT_WAV;
    dflt_data_fmt = SF_FORMAT_GSM610;

    delete = stereo = idprio = 0;
    dflags = D_FLAG_NONE;
    aname = oname = NULL;
    alice_crypto = bob_crypto = NULL;

    while ((ch = getopt_long(argc, argv, "dsinF:D:A:B:", longopts,
      &option_index)) != -1)
        switch (ch) {
        case 'd':
            delete = 1;
            break;

        case 's':
            stereo = 1;
            sfinfo.channels = 2;
            /* GSM+WAV doesn't work with more than 1 channels */
            dflt_data_fmt = SF_FORMAT_MS_ADPCM;
            break;

        case 'i':
            idprio = 1;
            break;

        case 'n':
            dflags |= D_FLAG_NOSYNC;
            break;

        case 'F':
            sf_of = pick_format(optarg, eaud_file_fmts);
            if (sf_of == NULL) {
                warnx("unknown output file format: \"%s\"", optarg);
                dump_formats_descr("Supported file formats:\n", eaud_file_fmts);
                exit(1);
            }
            use_file_fmt = sf_of->id;
            break;

        case 'D':
            sf_of = pick_format(optarg, eaud_data_fmts);
            if (sf_of == NULL) {
                warnx("unknown output data format: \"%s\"", optarg);
                dump_formats_descr("Supported data formats:\n", eaud_data_fmts);
                exit(1);
            }
            use_data_fmt = sf_of->id;
            break;

        case 'A':
            aname = optarg;
            break;

        case 'B':
            oname = optarg;
            break;

#if ENABLE_SRTP || ENABLE_SRTP2
        case LOPT_ALICE_CRYPTO:
            alice_crypto = eaud_crypto_getopt_parse(optarg);
            if (alice_crypto == NULL) {
                exit(1);
            }
            break;

        case LOPT_BOB_CRYPTO:
            bob_crypto = eaud_crypto_getopt_parse(optarg);
            if (bob_crypto == NULL) {
                exit(1);
            }
            break;
#endif

        case '?':
        default:
            usage();
        }
    argc -= optind;
    argv += optind;

    if (aname == NULL && oname == NULL && argc < 2)
        usage();

    if (use_file_fmt == 0) {
        use_file_fmt = dflt_file_fmt;
    }
    if (use_data_fmt == 0) {
        use_data_fmt = dflt_data_fmt;
    }

    if (idprio != 0) {
#if defined(__FreeBSD__)
        rt.type = RTP_PRIO_IDLE;
        rt.prio = RTP_PRIO_MAX;
        rtprio(RTP_SET, 0, &rt);
#else
        setpriority(PRIO_PROCESS, 0, 20);
#endif
    }

    if (aname == NULL && oname == NULL) {
        sprintf(aname_s, "%s.a.rtp", argv[0]);
        aname = aname_s;
        sprintf(oname_s, "%s.o.rtp", argv[0]);
        oname = oname_s;
        argv += 1;
        argc -= 1;
    }

    if (aname != NULL) {
        load_session(aname, &channels, A_CH, alice_crypto);
    }
    if (oname != NULL) {
        load_session(oname, &channels, O_CH, bob_crypto);
    }

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
        cp->decoder = decoder_new(&(cp->session), dflags);
        nch++;
    }

    oblen = 0;

    sfinfo.format = use_file_fmt | use_data_fmt;

    sffile = sf_open(argv[0], SFM_WRITE, &sfinfo);
    if (sffile == NULL)
        errx(2, "%s: can't open output file", argv[0]);
#if defined(EAUD_DUMPRAW)
    FILE *raw_file = fopen(EAUD_DUMPRAW, "w");
#endif

    nasamples = nosamples = nwsamples = 0;
    do {
        neof = 0;
        asample = osample = 0;
        seen_a = seen_o = 0;
        MYQ_FOREACH(cp, &channels) {
            if ((dflags & D_FLAG_NOSYNC) == 0) {
                if (cp->skip > 0) {
                    cp->skip--;
                    continue;
                }
            } else {
                if (cp->origin == A_CH && seen_a != 0)
                    continue;
                if (cp->origin == O_CH && seen_o != 0)
                    continue;
            }
            do {
                csample = decoder_get(cp->decoder);
            } while (csample == DECODER_SKIP);
            if (csample == DECODER_EOF || csample == DECODER_ERROR) {
                neof++;
                continue;
            }
            if (cp->origin == A_CH) {
                asample += csample;
                nasamples++;
                if (seen_a != 0) {
                    asample /= 2;
                } else {
                    seen_a = 1;
                }
            } else {
                osample += csample;
                nosamples++;
                if (seen_o != 0) {
                    osample /= 2;
                } else {
                    seen_o = 1;
                }
            }
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
#if defined(EAUD_DUMPRAW)
            fwrite(obuf, sizeof(int16_t), oblen, raw_file);
#endif
            sf_write_short(sffile, obuf, oblen);
            nwsamples += oblen / sizeof(obuf[0]);
            oblen = 0;
        }
    } while (neof < nch);
    fprintf(stderr, "samples decoded: O: %" PRIu64 ", A: %" PRIu64
      ", written: %" PRIu64 "\n", nosamples, nasamples, nwsamples);

#if defined(EAUD_DUMPRAW)
    fclose(raw_file);
#endif
    sf_close(sffile);

    while (argc > 1) {
        link(argv[0], argv[argc - 1]);
        argc--;
    }

theend:
    if (delete != 0) {
        if (aname != NULL) {
            unlink(aname);
        }
        if (oname != NULL) {
            unlink(oname);
        }
    }

    return 0;
}
