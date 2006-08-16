/*
 * Copyright (c) 2003-2006 Maxim Sobolev
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

#include <sys/endian.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "g711.h"
#include "g729_encoder.h"
#include "gsm.h"
#include "../rtp.h"

static void
usage(void)
{

    fprintf(stderr, "usage: makeann [-l limit [-L]] infile [outfile_template]\n");
    exit(1);
}

struct efile {
    FILE *f;
    rtp_type_t pt;
    char path[PATH_MAX + 1];
};

int main(int argc, char **argv)
{
    FILE *infile;
    uint8_t lawbuf[160];
    int16_t slbuf[160];
    int i, j, k, rsize, wsize, loop, limit, rlimit, ch;
    G729_CTX *ctx_g729;
    gsm ctx_gsm;
    const char *template;
    struct efile efiles[] = {{NULL, RTP_PCMU}, {NULL, RTP_GSM},
      {NULL, RTP_G729}, {NULL, RTP_PCMA}, {NULL, -1}};

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

    ctx_g729 = g729_encoder_new();
    if (ctx_g729 == NULL)
        errx(1, "can't create G.729 encoder");
    ctx_gsm = gsm_create();
    if (ctx_gsm == NULL)
        errx(1, "can't create GSM encoder");

    infile = fopen(argv[0], "r");
    if (infile == NULL)
        err(1, "can't open %s for reading", argv[0]);

    for (k = 0; efiles[k].pt != -1; k++) {
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
                slbuf[j] = le16toh(slbuf[j]);
            else
                slbuf[j] = 0;
        }
        for (k = 0; efiles[k].pt != -1; k++) {
            switch (efiles[k].pt) {
            case RTP_PCMU:
                SL2ULAW(lawbuf, slbuf, i);
                wsize = i;
                break;

            case RTP_PCMA:
                SL2ALAW(lawbuf, slbuf, i);
                wsize = i;
                break;

            case RTP_G729:
                for (j = 0; j < 2; j++)
                    g729_encode_frame(ctx_g729, &(slbuf[j * 80]), &(lawbuf[j * 10]));
                wsize = 20;
                break;

            case RTP_GSM:
                gsm_encode(ctx_gsm, slbuf, lawbuf);
                wsize = 33;
                break;

            default:
                abort();
            }
            if (fwrite(lawbuf, sizeof(lawbuf[0]), wsize, efiles[k].f) < wsize)
                errx(1, "can't write to %s", efiles[k].path);
        }
    }

    fclose(infile);
    for (k = 0; efiles[k].pt != -1; k++)
        fclose(efiles[k].f);

    return 0;
}
