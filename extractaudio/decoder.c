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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtp_info.h"
#include "decoder.h"
#include "g729_compat.h"
#include "session.h"
#include "rtpp_record_adhoc.h"
#include "rtpp_record_private.h"
#include "rtp.h"
#include "g711.h"

/* static char i[] = "0"; */

static unsigned int upsample2_flush(struct decoder_stream *, int16_t *);

void *
decoder_new(struct session *sp, int dflags, int orate)
{
    struct decoder_stream *dp;

    dp = malloc(sizeof(*dp));
    if (dp == NULL)
        return NULL;
    memset(dp, 0, sizeof(*dp));
    dp->pp = MYQ_FIRST(sp);
    if (dp->pp == NULL)
        /*
         * If the queue is empty return "as is", decoder_get() then'll be
         * responsible for generating DECODER_EOF.
         */
        return (void *)dp;
    dp->sp = sp;
    dp->obp = dp->obuf;
    dp->oblen = 0;
    dp->stime = dp->pp->pkt->time;
    dp->nticks = dp->sticks = dp->pp->parsed.ts;
    dp->dticks = 0;
    dp->lpt = RTP_PCMU;
    dp->dflags = dflags;
    dp->rmult = orate / 8000;
    /* dp->f = fopen(i, "w"); */
    /* i[0]++; */

    return (void *)dp;
}

int32_t
decoder_get(struct decoder_stream *dp)
{
    unsigned int cticks, t;
    int j;

    if (dp->oblen == 0 && dp->pp == NULL) {
        /* Drain the upsampler before reporting EOF */
        dp->oblen = upsample2_flush(dp, dp->obuf);
        dp->obp = dp->obuf;
    }
    if (dp->oblen == 0) {
        if (dp->pp == NULL)
            return DECODER_EOF;
        cticks = dp->pp->parsed.ts;
        /*
         * First of all check if we can trust timestamp contained in the
         * packet. If it's off by more than 1 second than the device
         * probably gone nuts and we can't trust it anymore.
         */
        if ((double)((cticks - dp->sticks) / 8000) > (dp->pp->pkt->time - dp->stime + 1.0)) {
            dp->nticks = cticks;
            dp->sticks = cticks - (dp->pp->pkt->time - dp->stime) * 8000;
        }
        if (dp->nticks < cticks) {
            t = cticks - dp->nticks;
            if (t > DECODER_MAX_GAP)
                t = DECODER_MAX_GAP;
            if ((dp->dflags & D_FLAG_NOSYNC) != 0) {
                dp->nticks += t;
                dp->dticks += t;
                return (DECODER_SKIP);
            }
            j = output_silence(dp, t);
            if (j < 0)
                return DECODER_ERROR;
            dp->nticks += t;
            dp->dticks += t;
            if (j == 0)
                return decoder_get(dp);
            dp->oblen = j / 2;
            dp->obp = dp->obuf;
        } else if ((dp->pp->pkt->time - dp->stime - (double)dp->dticks / 8000.0) > 0.2) {
            t = (((dp->pp->pkt->time - dp->stime) * 8000) - dp->dticks) / 2;
            if (t > DECODER_MAX_GAP)
                t = DECODER_MAX_GAP;
            if ((dp->dflags & D_FLAG_NOSYNC) != 0) {
                dp->dticks += t;
                return (DECODER_SKIP);
            }
            j = output_silence(dp, t);
            if (j < 0)
                return DECODER_ERROR;
            dp->dticks += t;
            if (j == 0)
                return decoder_get(dp);
            dp->oblen = j / 2;
            dp->obp = dp->obuf;
        } else {
            j = output_frame(dp);
            dp->pp = MYQ_NEXT(dp->pp);
            if (j <= 0)
                return decoder_get(dp);
            dp->oblen = j / 2;
            dp->obp = dp->obuf;
        }
    }
    dp->oblen--;
    dp->obp += 1;
    return *(dp->obp - 1);
}

int
decode_frame(struct decoder_stream *dp, int16_t *obuf, unsigned char *ibuf,
  unsigned int ibytes, unsigned int obytes_max)
{
    unsigned int obytes;

    switch (dp->pp->rpkt->pt) {
    case RTP_PCMU:
        if (obytes_max < (ibytes * 2)) {
            ibytes = obytes_max / 2;
        }
        ULAW2SL(obuf, ibuf, ibytes);
        dp->nticks += ibytes;
        dp->dticks += ibytes;
        return ibytes * 2;

    case RTP_PCMA:
        if (obytes_max < (ibytes * 2)) {
            ibytes = obytes_max / 2;
        }
        ALAW2SL(obuf, ibuf, ibytes);
        dp->nticks += ibytes;
        dp->dticks += ibytes;
        return ibytes * 2;

#ifdef ENABLE_G729
    case RTP_G729: {
        int fsize;
        void *bp;

        /* fwrite(ibuf, ibytes, 1, dp->f); */
        /* fflush(dp->f); */
        if (ibytes % 10 == 0)
            fsize = 10;
        else if (ibytes % 8 == 0)
            fsize = 8;
        else if (ibytes % 15 == 0)
            fsize = 15;
        else if (ibytes % 2 == 0)
            fsize = 2;
        else
            return -1;
        if (dp->g729_ctx == NULL)
            dp->g729_ctx = G729_DINIT();
        if (dp->g729_ctx == NULL)
            return -1;
        for (obytes = 0; ibytes > 0 && obytes <= obytes_max - 160; ibytes -= fsize) {
            bp = G729_DECODE(dp->g729_ctx, ibuf, fsize);
            ibuf += fsize;
            memcpy(obuf, bp, 160);
            obuf += 80;
            obytes += 160;
            dp->nticks += 80;
            dp->dticks += 80;
        }
        return obytes;
    }
#endif

#ifdef ENABLE_G722
    case RTP_G722:
        if (dp->g722_ctx == NULL)
            dp->g722_ctx = g722_decoder_new(64000,
              dp->rmult == 2 ? 0 : G722_SAMPLE_RATE_8000);
        if (dp->g722_ctx == NULL)
            return -1;
        /* One RTP tick per byte; rmult output samples per tick */
        if (obytes_max < (ibytes * 2 * dp->rmult)) {
            ibytes = obytes_max / (2 * dp->rmult);
        }
        g722_decode(dp->g722_ctx, ibuf, ibytes, obuf);
        dp->nticks += ibytes;
        dp->dticks += ibytes;
        return ibytes * 2 * dp->rmult;
#endif

#ifdef ENABLE_GSM
    case RTP_GSM:
        if (dp->ctx_gsm == NULL) {
            dp->ctx_gsm = gsm_create();
            if (dp->ctx_gsm == NULL) {
                fprintf(stderr, "can't create GSM decoder\n");
                return (-1);
            }
        }
        if (ibytes < 33) {
            return (-1);
        }
        for (obytes = 0; ibytes > 0 && obytes <= obytes_max - 320; ibytes -= 33) {
            gsm_decode(dp->ctx_gsm, ibuf, obuf);
            ibuf += 33;
            obuf += 160;
            obytes += 320;
            dp->nticks += 160;
            dp->dticks += 160;
        }
        return obytes;
#endif

    case RTP_CN:
    case RTP_TSE:
    case RTP_TSE_CISCO:
        return 0;

    default:
        return -1;
    }
}

int
generate_silence(struct decoder_stream *dp, int16_t *obuf, unsigned int iticks)
{

    switch (dp->lpt) {
    case RTP_PCMU:
    case RTP_PCMA:
    case RTP_G723:
    case RTP_G722:
    case RTP_GSM:
        memset(obuf, 0, iticks * 2);
        return iticks * 2;

#ifdef ENABLE_G729
    case RTP_G729: {
#ifndef ENABLE_BCG729
        unsigned int obytes;
        void *bp;
        if (dp->g729_ctx == NULL)
            dp->g729_ctx = G729_DINIT();
        if (dp->g729_ctx == NULL) {
            memset(obuf, 0, iticks * 2);
            return iticks * 2;
        }
        for (obytes = 0; iticks >= 80; iticks -= 80) {
            bp = G729_DECODE(dp->g729_ctx, NULL, 0);
            memcpy(obuf, bp, 160);
            obuf += 80;
            obytes += 160;
        }
        if (iticks > 0) {
            memset(obuf, 0, iticks * 2);
            obytes += iticks * 2;
        }
        return obytes;
#else
        memset(obuf, 0, iticks * 2);
        return iticks * 2;
#endif
    }
#endif

    default:
        return -1;
    }
}

/*
 * 2x upsampler for narrowband (8 KHz) decoder output. Even output samples are
 * the input samples, odd ones the midpoint of a 16-tap Blackman-windowed sinc
 * half-band interpolator (flat to 3 KHz, -1.6 dB at 3.4 KHz).
 *
 * The interpolator needs US_HALF input samples of look-ahead. To keep the
 * output aligned with native 16 KHz (G.722) output, each narrowband run starts
 * from a clear history and drops the first 2 * US_HALF output samples, and
 * upsample2_flush() emits the held back samples when the run ends. A run of
 * N input samples thus yields exactly 2 * N output samples with no delay.
 */
static const int32_t us_coef[US_HALF] = {
    20570, -6124, 2918, -1457, 684, -282, 93, -18
};

/* Returns number of output samples, which is less than 2 * n at run start */
static unsigned int
upsample2(struct decoder_stream *dp, int16_t *out, const int16_t *in,
  unsigned int n)
{
    int16_t *h = dp->us_hist;
    unsigned int i, k, no;
    int32_t mid;

    if (dp->us_active == 0) {
        memset(h, 0, sizeof(dp->us_hist));
        dp->us_skip = 2 * US_HALF;
        dp->us_active = 1;
    }
    for (i = no = 0; i < n; i++) {
        memmove(h, h + 1, (2 * US_HALF - 1) * sizeof(h[0]));
        h[2 * US_HALF - 1] = in[i];
        if (dp->us_skip > 0) {
            dp->us_skip -= 2;
            continue;
        }
        mid = 0;
        for (k = 0; k < US_HALF; k++)
            mid += us_coef[k] * ((int32_t)h[US_HALF - 1 - k] +
              (int32_t)h[US_HALF + k]);
        mid = (mid + (1 << 14)) >> 15;
        if (mid > INT16_MAX)
            mid = INT16_MAX;
        else if (mid < INT16_MIN)
            mid = INT16_MIN;
        out[no++] = h[US_HALF - 1];
        out[no++] = (int16_t)mid;
    }
    return no;
}

/* End the current narrowband run, if any; returns number of output samples */
static unsigned int
upsample2_flush(struct decoder_stream *dp, int16_t *out)
{
    static const int16_t zeros[US_HALF];
    unsigned int no;

    if (dp->us_active == 0)
        return 0;
    no = upsample2(dp, out, zeros, US_HALF);
    dp->us_active = 0;
    return no;
}

/*
 * Decode the current packet into dp->obuf at the output rate and update
 * dp->lpt. Returns number of bytes in dp->obuf, which may be 0, or < 0.
 */
int
output_frame(struct decoder_stream *dp)
{
    unsigned int n;
    int j;

    if (dp->rmult == 1 || dp->pp->rpkt->pt == RTP_G722) {
        n = upsample2_flush(dp, dp->obuf);
        /*
         * Decode at most DECODER_MAX_TICKS per packet at any output rate, so
         * oversized packets are cut at the same point at 8 and 16 KHz.
         */
        j = decode_frame(dp, dp->obuf + n, RPLOAD(dp->pp), RPLEN(dp->pp),
          (DECODER_MAX_TICKS * dp->rmult - n) * sizeof(dp->obuf[0]));
        if (j > 0)
            dp->lpt = dp->pp->rpkt->pt;
        if (j < 0)
            return (n > 0) ? (int)(n * sizeof(dp->obuf[0])) : j;
        return j + (int)(n * sizeof(dp->obuf[0]));
    }
    j = decode_frame(dp, dp->nbuf, RPLOAD(dp->pp), RPLEN(dp->pp),
      sizeof(dp->nbuf));
    if (j <= 0)
        return j;
    dp->lpt = dp->pp->rpkt->pt;
    return upsample2(dp, dp->obuf, dp->nbuf, j / 2) * 2;
}

/*
 * Fill dp->obuf with iticks RTP ticks of silence at the output rate. Returns
 * number of bytes in dp->obuf, which may be 0, or < 0.
 */
int
output_silence(struct decoder_stream *dp, unsigned int iticks)
{
    int j;

    if (dp->rmult == 1)
        return generate_silence(dp, dp->obuf, iticks);
    if (dp->lpt == RTP_G722) {
        /* No narrowband run can be active after a G.722 frame */
        memset(dp->obuf, 0, iticks * 2 * dp->rmult);
        return iticks * 2 * dp->rmult;
    }
    j = generate_silence(dp, dp->nbuf, iticks);
    if (j <= 0)
        return j;
    return upsample2(dp, dp->obuf, dp->nbuf, j / 2) * 2;
}
