/*
 * Copyright (c) 2003-2006 Maxim Sobolev <sobomax@FreeBSD.org>
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

#if defined(HAVE_CONFIG_H)
#include "config_pp.h"
#endif

#include <sys/socket.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if !defined(NO_ERR_H)
#include <err.h>
#else
#include "rtpp_util.h"
#endif

#include "g711.h"

#ifdef ENABLE_G729
# include "g729_compat.h"
# define G729_ENABLED 1
#else
# define G729_ENABLED 0
#endif

#ifdef ENABLE_GSM
#include "gsm.h"
#define GSM_ENABLED 1
#else
#define GSM_ENABLED 0
#endif

#ifdef ENABLE_G722
#include "g722_encoder.h"
#define G722_ENABLED 1
#else
#define G722_ENABLED 0
#endif

#include "rtp.h"

#if BYTE_ORDER == BIG_ENDIAN
#define LE16_2_HOST(x) \
 ((((uint16_t)(x)) >> 8) & 0xff) | ((((uint16_t)(x)) & 0xff) << 8)
#else
#define LE16_2_HOST(x) (x)
#endif

static void
usage(void)
{

    fprintf(stderr, "usage: makeann [-l limit [-L]] infile [outfile_template]\n");
    exit(1);
}

struct efile {
    FILE *f;
    rtp_type_t pt;
    int enabled;
    char path[PATH_MAX + 1];
};

int main(int argc, char **argv)
{
    FILE *infile;
    uint8_t lawbuf[160];
    int16_t slbuf[160];
    int i, j, k, rsize, wsize, loop, limit, rlimit, ch;
#ifdef ENABLE_G729
    G729_ECTX *ctx_g729;
#endif
#ifdef ENABLE_GSM
    gsm ctx_gsm;
#endif
#ifdef ENABLE_G722
    G722_ENC_CTX *ctx_g722;
#endif
    const char *template;
    struct efile efiles[] = {{NULL, RTP_PCMU, 1}, {NULL, RTP_GSM, GSM_ENABLED},
      {NULL, RTP_G729, G729_ENABLED}, {NULL, RTP_PCMA, 1},
      {NULL, RTP_G722, G722_ENABLED}, {NULL, RTP_UNKN, 0}};

    loop = 0;
    limit = -1;
    while ((ch = getopt(argc, argv, "l:L")) != -1)
        switch (ch) {
        case 'l':
            limit = atoi(optarg);
            break;

        case 'L':
            loop = 1;
            break;

        case '?':
        default:
            usage();
        }
    argc -= optind;
    argv += optind;

    if (argc < 1 || argc > 2)
        usage();

    if (loop != 0 && limit == -1)
        errx(1, "limit have to be specified in the loop mode");

    if (argc == 2)
        template = argv[1];
    else
        template = argv[0];

#ifdef ENABLE_G729
    ctx_g729 = G729_EINIT();
    if (ctx_g729 == NULL)
        errx(1, "can't create G.729 encoder");
#endif
#ifdef ENABLE_GSM
    ctx_gsm = gsm_create();
    if (ctx_gsm == NULL)
        errx(1, "can't create GSM encoder");
#endif
#ifdef ENABLE_G722
    ctx_g722 = g722_encoder_new(64000, G722_SAMPLE_RATE_8000);
    if (ctx_g722 == NULL)
        errx(1, "can't create G.722 encoder");
#endif

    infile = fopen(argv[0], "r");
    if (infile == NULL)
        err(1, "can't open %s for reading", argv[0]);

    for (k = 0; efiles[k].pt != RTP_UNKN; k++) {
        if (efiles[k].enabled == 0)
            continue;
        sprintf(efiles[k].path, "%s.%d", template, efiles[k].pt);
        efiles[k].f = fopen(efiles[k].path, "w");
        if (efiles[k].f == NULL)
            err(1, "can't open %s for writing", efiles[k].path);
    }

    for (rlimit = limit; limit == -1 || rlimit > 0; rlimit -= i) {
        rsize = (limit == -1 || rlimit > 160) ? 160 : rlimit;
        i = fread(slbuf, sizeof(slbuf[0]), rsize, infile);
        if (i < rsize && feof(infile) && loop != 0) {
            rewind(infile);
            i += fread(slbuf + i, sizeof(slbuf[0]), rsize - i, infile);
        }
        if (i == 0)
            break;
        for (j = 0; j < 160; j++) {
            if (j < i)
                slbuf[j] = LE16_2_HOST(slbuf[j]);
            else
                slbuf[j] = 0;
        }
        for (k = 0; efiles[k].pt != RTP_UNKN; k++) {
            if (efiles[k].enabled == 0)
                continue;
            switch (efiles[k].pt) {
            case RTP_PCMU:
                SL2ULAW(lawbuf, slbuf, i);
                wsize = i;
                break;

            case RTP_PCMA:
                SL2ALAW(lawbuf, slbuf, i);
                wsize = i;
                break;

#ifdef ENABLE_G729
            case RTP_G729:
                for (j = 0; j < 2; j++) {
                    uint8_t l;
                    G729_ENCODE(ctx_g729, &(slbuf[j * 80]), &(lawbuf[j * 10]), &l);
                    wsize += l;
                }
                break;
#endif

#ifdef ENABLE_GSM
            case RTP_GSM:
                gsm_encode(ctx_gsm, slbuf, lawbuf);
                wsize = 33;
                break;
#endif

#ifdef ENABLE_G722
            case RTP_G722:
                for (j = 0; j < 2; j++)
                    g722_encode(ctx_g722, &(slbuf[j * 80]), 80, &(lawbuf[j * 80]));
                wsize = 160;
                break;
#endif

            default:
                abort();
            }
            if (fwrite(lawbuf, sizeof(lawbuf[0]), wsize, efiles[k].f) < wsize)
                errx(1, "can't write to %s", efiles[k].path);
        }
    }

    fclose(infile);
    for (k = 0; efiles[k].pt != RTP_UNKN; k++) {
        if (efiles[k].enabled == 0)
            continue;
        fclose(efiles[k].f);
    }

#ifdef ENABLE_G729
    G729_ECLOSE(ctx_g729);
#endif

    return 0;
}
