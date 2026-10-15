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

#ifndef _DECODER_H_
#define _DECODER_H_

#include <sys/types.h>

#include "config.h"

#ifdef ENABLE_G729
#include "g729_compat.h"
#endif
#ifdef ENABLE_G722
#include <g722_decoder.h>
#endif
#ifdef ENABLE_GSM
#include "gsm.h"
#endif

#include "rtp.h"
#include "session.h"

#define	DECODER_EOF	(-(1 << 16))
#define	DECODER_ERROR	(-(2 << 16))
#define	DECODER_SKIP	(-(3 << 16))

#define	US_HALF	8	/* upsampler taps on each side of the midpoint */

/* Most 8 KHz RTP ticks decoded at once, ~0.5 seconds */
#define	DECODER_MAX_TICKS	(4 * 1024)
/* Most output samples per RTP tick: 2 at 16 KHz */
#define	DECODER_MAX_RMULT	2
/* Most RTP ticks of silence inserted at once to fill a gap */
#define	DECODER_MAX_GAP		4000

#if DECODER_MAX_GAP > DECODER_MAX_TICKS
#error "DECODER_MAX_GAP has to fit into the decoder buffers"
#endif

struct decoder_stream {
    struct session *sp;
    struct packet *pp;
    unsigned int nticks;
    unsigned int sticks;
    unsigned char lpt;
    /* Output at up to 16 KHz, 16 bits per sample */
    int16_t obuf[DECODER_MAX_TICKS * DECODER_MAX_RMULT];
    /* Narrowband 8 KHz decoder output, before upsampling */
    int16_t nbuf[DECODER_MAX_TICKS];
    int16_t *obp;
    unsigned int oblen;
    int rmult;			/* output samples per 8 KHz RTP tick: 1 or 2 */
    int16_t us_hist[2 * US_HALF];	/* upsampler history */
    int us_active;		/* upsampler is inside a narrowband run */
    unsigned int us_skip;	/* priming output samples still to drop */
#ifdef ENABLE_G729
    G729_DCTX *g729_ctx;
#endif
#ifdef ENABLE_G722
    G722_DEC_CTX *g722_ctx;
#endif
#ifdef ENABLE_GSM
    gsm ctx_gsm;
#endif
    double stime;
    double dticks;
    /* FILE *f; */
    int dflags;
};

#define D_FLAG_NONE      0x0
#define D_FLAG_NOSYNC    0x1
#define D_FLAG_ERRFAIL   0x2

void *decoder_new(struct session *, int, int);
int32_t decoder_get(struct decoder_stream *);
int decode_frame(struct decoder_stream *, int16_t *, unsigned char *,
  unsigned int, unsigned int);
int generate_silence(struct decoder_stream *, int16_t *, unsigned int);
int output_frame(struct decoder_stream *);
int output_silence(struct decoder_stream *, unsigned int);

#endif
