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
#include <err.h>

#include "config.h"

#include "rtp_info.h"
#include "decoder.h"
#include "g729_compat.h"
#include "session.h"
#include "rtpp_record_private.h"
#include "rtp.h"
#include "g711.h"

/* static char i[] = "0"; */

void *
decoder_new(struct session *sp, int dflags)
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
    dp->silence_at_receiver = dp->silence_from_sender = 0;
    dp->lpt = RTP_PCMU;
    dp->dflags = dflags;
    /* dp->f = fopen(i, "w"); */
    /* i[0]++; */

    return (void *)dp;
}

static
unsigned int
extract_some_pending_silence(struct decoder_stream *dp)
{
    unsigned int t;

    if (dp->silence_at_receiver > 0) {
	/* Handle overlapping silences.
	** If the sender has a gap in the timestamps AND packets arrive later
	** than playout time, we do not want to double up the generated silence.
	** So we elide any silence caused by late arrivals that is covered by
	** the period of sender-indicated silence.
	*/
	if (dp->silence_from_sender > 0) {
	    warnx("Silence overlap: explicit sender gap of %u ticks, inferred silence of %u ticks at receiver", dp->silence_from_sender, dp->silence_at_receiver);
	    if (dp->silence_at_receiver >= dp->silence_from_sender)
		dp->silence_at_receiver -= dp->silence_from_sender;
	    else
		dp->silence_at_receiver = 0;
	}
	t = dp->silence_at_receiver;
	if (t > 4000)
	    t = 4000;
	dp->silence_at_receiver -= t;
	if (t > 0) return t;
    }

    t = dp->silence_from_sender;
    if (t > 4000)
	t = 4000;
    dp->silence_from_sender -= t;
    return t;
}

int32_t
decoder_get(struct decoder_stream *dp)
{
    unsigned int cticks, t;
    int j;

    while (dp->oblen <= 0) {
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
        /* Calculate sender-indicated silence between the expected timestamp and the current one. */
        if (dp->nticks < cticks) {
            t = cticks - dp->nticks;
            dp->nticks += t;
            if ((dp->dflags & D_FLAG_NOSYNC) != 0)
                return (DECODER_SKIP);
            dp->silence_from_sender += t;
        }
        t = extract_some_pending_silence(dp);
        if (t > 0) {
            j = generate_silence(dp, dp->obuf, t);
            if (j <= 0)
                return DECODER_ERROR;
            dp->dticks += t;
            dp->oblen = j / 2;
            dp->obp = dp->obuf;
        } else {
            /* Calculate receiver-detected silence from packet arrival time
            ** compared to playout time.
            ** We do not generate silence immediately, because we want the
            ** generated silence to follow the audio, and possibly be
            ** subsumed into any sender-indicated silence.
            ** We do not infer silence if there is no audio payload, because
            ** we want the silence to prefix the next actual audio data.
            */
            if (RPLEN(dp->pp) > 0 && (dp->pp->pkt->time - dp->stime - dp->dticks / 8000.0) > 0.2) {
                t = (((dp->pp->pkt->time - dp->stime) * 8000) - dp->dticks) / 2;
                if ((dp->dflags & D_FLAG_NOSYNC) != 0) {
                    dp->dticks += t;
                    return (DECODER_SKIP);
                }
                dp->silence_at_receiver += t;
            }
            j = decode_frame(dp, dp->obuf, RPLOAD(dp->pp), RPLEN(dp->pp), \
              sizeof(dp->obuf));
            if (j > 0)
                dp->lpt = dp->pp->rpkt->pt;
            dp->pp = MYQ_NEXT(dp->pp);
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
            dp->g722_ctx = g722_decoder_new(64000, G722_SAMPLE_RATE_8000);
        if (dp->g722_ctx == NULL)
            return -1;
        if (obytes_max < (ibytes * 2)) {
            ibytes = obytes_max / 2;
        }
        g722_decode(dp->g722_ctx, ibuf, ibytes, obuf);
        dp->nticks += ibytes;
        dp->dticks += ibytes;
        return ibytes * 2;
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
            obuf += 160;
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
