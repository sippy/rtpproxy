/* $Id$ */

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "g711.h"
#include "g729_encoder.h"
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
    uint8_t lawbuf[80];
    int16_t slbuf[80];
    int i, j, k, rsize, wsize, loop, limit, rlimit, ch;
    G729_CTX *ctx;
    const char *template;
    struct efile efiles[] = {{NULL, RTP_PCMU},
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

    ctx = g729_encoder_new();
    if (ctx == NULL)
        errx(1, "can't create G.729 encoder");

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
        rsize = (limit == -1 || rlimit > 80) ? 80 : rlimit;
        i = fread(slbuf, sizeof(slbuf[0]), rsize, infile);
        if (i < rsize && feof(infile) && loop != 0) {
            rewind(infile);
            i += fread(slbuf + i, sizeof(slbuf[0]), rsize - i, infile);
        }
        if (i == 0)
            break;
        for (j = i; j < 80; j++)
            slbuf[j] = 0;
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
                g729_encode_frame(ctx, slbuf, lawbuf);
                wsize = 10;
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
