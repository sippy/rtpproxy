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
#include <assert.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sndfile.h>

#include "config.h"

#if HAVE_ERR_H
# include <err.h>
#endif

#include "rtpp_types.h"
#include "format_au.h"
#include "g711.h"
#include "rtp_info.h"
#include "decoder.h"
#include "eaud_channels.h"
#include "eaud_session.h"
#include "rtpp_record_adhoc.h"
#include "rtpp_record_private.h"
#include "rtpp_ssrc.h"
#include "rtp_analyze.h"
#include "rtpp_loader.h"
#include "rtp.h"
#include "eaud_oformats.h"
#if ENABLE_SRTP || ENABLE_SRTP2
# include "eaud_crypto.h"
#endif
#include "eaud_substreams.h"

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

#ifdef RTPP_CHECK_LEAKS
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

const static char *usage_msg[8] = {
  "%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
  "usage: extractaudio [-idsne] [-F file_fmt] [-D data_fmt] rdir outfile",
  "                    [link1] ... [linkN]",
  "       extractaudio [-idsne] [-F file_fmt] [-D data_fmt] [-A answer_cap]",
  "                    [-B originate_cap] [--alice-crypto CSPEC]",
  "                    [--bob-crypto CSPEC] outfile [link1] ... [linkN]",
  "       extractaudio -S [-A answer_cap] [-B originate_cap]",
  "       extractaudio -S rdir"
};

static void
usage(void)
{

    fprintf(stderr, usage_msg[0], usage_msg[1], usage_msg[2], usage_msg[3],
      usage_msg[4], usage_msg[5], usage_msg[6], usage_msg[7]);
    exit(1);
}

int
main(int argc, char **argv)
{
    int ch, seen_a, seen_b;
    int oblen, delete, stereo, idprio, nch, neof;
    int32_t bsample, asample, csample;
    uint64_t nasamples, nbsamples, nwsamples;
    struct channels channels, act_subset, *ap;
    struct cnode *cnp;
#if defined(__FreeBSD__)
    struct rtprio rt;
#endif
    int16_t obuf[1024];
    char aname_s[MAXPATHLEN], bname_s[MAXPATHLEN];
    const char *aname, *bname, *uname;
    double basetime;
    SF_INFO sfinfo;
    SNDFILE *sffile;
    int dflags, nloaded;
    const struct supported_fmt *sf_of;
    uint32_t use_file_fmt, use_data_fmt;
    uint32_t dflt_file_fmt, dflt_data_fmt;
    int option_index;
    struct eaud_crypto *alice_crypto, *bob_crypto;
    int64_t isample, sync_sample;

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_APP_INIT();
#endif

    MYQ_INIT(&channels);
    MYQ_INIT(&act_subset);
    memset(&sfinfo, 0, sizeof(sfinfo));
    sfinfo.samplerate = 8000;
    sfinfo.channels = 1;
    use_file_fmt = use_data_fmt = 0;
    dflt_file_fmt = SF_FORMAT_WAV;
    dflt_data_fmt = SF_FORMAT_GSM610;

    delete = stereo = idprio = 0;
    dflags = D_FLAG_NONE;
    aname = bname = NULL;
    alice_crypto = bob_crypto = NULL;
    isample = -1;
    sync_sample = 0;
    int scanonly = 0;

    while ((ch = getopt_long(argc, argv, "dsSineF:D:A:B:U:", longopts,
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
            bname = optarg;
            break;

        case 'U':
            uname = optarg;
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

        case 'S':
            scanonly = 1;
            break;

        case 'e':
            dflags |= D_FLAG_ERRFAIL;
            break;

        case '?':
        default:
            usage();
        }
    argc -= optind;
    argv += optind;

    if (aname == NULL && bname == NULL) {
        if ((argc < 2 && !scanonly) || (scanonly && argc != 1))
            usage();
    } else if ((argc == 0 && !scanonly) || (scanonly && argc != 0)) {
        usage();
    }

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

    if (aname == NULL && bname == NULL) {
        sprintf(aname_s, "%s.a.rtp", argv[0]);
        aname = aname_s;
        sprintf(bname_s, "%s.o.rtp", argv[0]);
        bname = bname_s;
        argv += 1;
        argc -= 1;
    }

    if (scanonly) {
        if (aname != NULL) {
            printf("%s: %d\n", aname, eaud_session_scan(aname));
        }
        if (bname != NULL) {
            printf("%s: %d\n", bname, eaud_session_scan(bname));
        }
        exit (0);
    }

    nloaded = 0;
    if (aname != NULL) {
        if (eaud_session_load(aname, &channels, A_CH, alice_crypto) >= 0) {
            nloaded += 1;
        } else if (dflags & D_FLAG_ERRFAIL) {
            errx(1, "cannot load %s", aname);
        }
    }
    if (bname != NULL) {
        if (eaud_session_load(bname, &channels, B_CH, bob_crypto) >= 0) {
            nloaded += 1;
        } else if (dflags & D_FLAG_ERRFAIL) {
            errx(1, "cannot load %s", bname);
        }
    }
    if (nloaded == 0) {
       errx(1, "cannot load neither %s nor %s", aname, bname);
    }

    if (MYQ_EMPTY(&channels))
        goto theend;

    MYQ_FOREACH(cnp, &channels) {
        cnp->cp->btime = MYQ_FIRST(&(cnp->cp->session))->pkt->time;
        cnp->cp->etime = MYQ_LAST(&(cnp->cp->session))->pkt->time;
    }

    nch = 0;
    basetime = MYQ_FIRST(&channels)->cp->btime;
#if 0
    fprintf(stderr, "%f %f\n", MYQ_FIRST(&(MYQ_FIRST(&channels)->session))->pkt->time, MYQ_FIRST(&channels)->btime);
#endif
    MYQ_FOREACH(cnp, &channels) {
        if (basetime > cnp->cp->btime)
            basetime = cnp->cp->btime;
    }
    MYQ_FOREACH(cnp, &channels) {
        cnp->cp->skip = (cnp->cp->btime - basetime) * 8000;
        cnp->cp->decoder = decoder_new(&(cnp->cp->session), dflags);
        if (cnp->cp->decoder == NULL)
            err(1, "decoder_new() failed");
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

    nasamples = nbsamples = nwsamples = 0;
    do {
        neof = 0;
        asample = bsample = 0;
        seen_a = seen_b = 0;
        isample += 1;
        if ((dflags & D_FLAG_NOSYNC) == 1) {
            ap = &channels;
        } else if (sync_sample == isample) {
            if (eaud_ss_syncactive(&channels, &act_subset, isample, &sync_sample) < 0)
                errx(1, "eaud_ss_syncactive() failed");
            ap = &act_subset;
        }
        MYQ_FOREACH(cnp, ap) {
restart:
            if ((dflags & D_FLAG_NOSYNC) == 0) {
                if (cnp->cp->skip > isample) {
                    continue;
                }
            } else {
                if (cnp->cp->origin == A_CH && seen_a != 0)
                    continue;
                if (cnp->cp->origin == B_CH && seen_b != 0)
                    continue;
            }
            do {
                csample = decoder_get(cnp->cp->decoder);
            } while (csample == DECODER_SKIP);
            if (csample == DECODER_EOF) {
                struct cnode *tnp;

                tnp = eaud_ss_find(&channels, cnp->cp);
                assert(tnp != NULL);
                channel_remove(&channels, tnp);
                if (ap != &channels) {
                    channel_remove(ap, cnp);
                }
                nch -= 1;
                cnp = MYQ_NEXT(cnp);
                if (cnp == NULL)
                    goto out;
                goto restart;
            }
            if (csample == DECODER_ERROR) {
                neof++;
                continue;
            }
            if (cnp->cp->origin == A_CH) {
                asample += csample;
                nasamples++;
                if (seen_a != 0) {
                    asample /= 2;
                } else {
                    seen_a = 1;
                }
            } else {
                bsample += csample;
                nbsamples++;
                if (seen_b != 0) {
                    bsample /= 2;
                } else {
                    seen_b = 1;
                }
            }
        }
out:
        if (neof < nch) {
            if (stereo == 0) {
                obuf[oblen] = (asample + bsample) / 2;
                oblen += 1;
            } else {
                obuf[oblen] = asample;
                oblen += 1;
                obuf[oblen] = bsample;
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
      ", written: %" PRIu64 "\n", nbsamples, nasamples, nwsamples);

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
        if (bname != NULL) {
            unlink(bname);
        }
    }

    return 0;
}
