/*
 * Copyright (c) 2007-2008 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <stddef.h>

#include "rtp.h"
#include "rtp_info.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_mallocs.h"

#include "rtpp_wi.h"
#include "rtpp_wi_private.h"

#define RTP_PROFILE_AUDIO(s, nc) {.ts_rate = (s), .sample_rate = (s), \
  .pt_kind = RTP_PTK_AUDIO, .nchannels = (nc)}

const struct rtp_profile rtp_profiles[128] = {
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_PCMU */
    {.pt_kind = RTP_PTK_RES},    /* Reserved */
    {.pt_kind = RTP_PTK_RES},    /* Reserved */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_GSM */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_G723 */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_DVI4_8000 */
    RTP_PROFILE_AUDIO(16000, 1), /* RTP_DVI4_16000 */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_LPC */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_PCMA */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_G722 */
    RTP_PROFILE_AUDIO(44100, 1), /* RTP_L16_MONO */
    RTP_PROFILE_AUDIO(44100, 2), /* RTP_L16_STEREO */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_QCELP */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_CN */
    RTP_PROFILE_AUDIO(90000, 2), /* RTP_MPA */
    RTP_PROFILE_AUDIO(8000,  1), /* RTP_G728 */
    RTP_PROFILE_AUDIO(11025, 1), /* RTP_DVI4_11025 */
    RTP_PROFILE_AUDIO(22050, 1), /* RTP_DVI4_22050 */
    RTP_PROFILE_AUDIO(8000,  1)  /* RTP_G729 */
};

struct rtp_packet_full;

struct rtp_packet_priv {
    struct rtp_info rinfo;
    struct rtpp_wi wi;
};

struct rtp_packet_full {
    struct rtp_packet pub;
    struct rtp_packet_priv pvt;
};

static int 
g723_len(unsigned char ch)
{

    switch (ch & 3) {
    case 2:
	/* Silence Insertion Descriptor (SID) frame */
	return 4;

    case 0:
	/* 6.3 kbit/s frame */
	return 24;

    case 1:
	/* 5.3 kbit/s frame */
	return 20;

    default:
	return RTP_NSAMPLES_UNKNOWN;
    }
}

static int 
g723_samples(const unsigned char *buf, int maxlen)
{
    int pos, samples, n;

    for (pos = 0, samples = 0; pos < maxlen; pos += n) {
	samples += 240;
	n = g723_len(buf[pos]);
	if (n == RTP_NSAMPLES_UNKNOWN)
	    return RTP_NSAMPLES_UNKNOWN;
    }
    return samples;
}

static int 
rtp_calc_samples(int codec_id, size_t nbytes, const unsigned char *data)
{

    switch (codec_id) {
	case RTP_PCMU:
	case RTP_PCMA:
	    return nbytes;

	case RTP_G729:
	    return (nbytes / 10) * 80 + (nbytes % 10 == 0 ? 0 : 80);

	case RTP_GSM:
	    return 160 * (nbytes / 33);

	case RTP_G723:
	    return g723_samples(data, nbytes);

	case RTP_G722:
	    return nbytes;

	default:
	    return RTP_NSAMPLES_UNKNOWN;
    }
}

static void
rtp_packet_chunk_find_g711(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{

    ret->nsamples = min_nsamples;
    ret->bytes = min_nsamples;
}

static void
rtp_packet_chunk_find_g729(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{
    int frames, samples;

    frames = min_nsamples / 80 + ((min_nsamples % 80) == 0 ? 0 : 1);
    samples = frames * 80;

    if (samples >= pkt->parsed->nsamples) {
	ret->whole_packet_matched = 1;
	return;
    }
    ret->nsamples = samples;
    ret->bytes = frames * 10;
}

static void
rtp_packet_chunk_find_gsm(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{
    int frames, samples;

    frames = min_nsamples / 160 + ((min_nsamples % 160) == 0 ? 0 : 1);
    samples = frames * 160;

    if (samples >= pkt->parsed->nsamples) {
	ret->whole_packet_matched = 1;
	return;
    }
    ret->nsamples = samples;
    ret->bytes = frames * 33;
}

static void
rtp_packet_chunk_find_g723(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{
    int frames, samples, pos, found_samples, n;
    unsigned char *buf;

    frames = min_nsamples / 240 + ((min_nsamples % 240) == 0 ? 0 : 1);
    samples = frames * 240;

    pos = 0;
    found_samples = 0;
    if (samples >= pkt->parsed->nsamples) {
	ret->whole_packet_matched = 1;
	return;
    }

    buf = &pkt->data.buf[pkt->parsed->data_offset];
    while (pos < pkt->parsed->data_size && samples > found_samples) {
	found_samples += 240;
	n = g723_len(buf[pos]);
	assert(n != RTP_NSAMPLES_UNKNOWN);
	pos += n;
    }
    ret->nsamples = found_samples;
    ret->bytes = (pos < pkt->parsed->data_size ? pos : pkt->parsed->data_size);
}

static void
rtp_packet_chunk_find_g722(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{
    ret->nsamples = min_nsamples;
    ret->bytes = min_nsamples / 2;
}


/* 
 * Find the head of the packet with the length at least 
 * of min_nsamples.
 *
 * Warning! When whole packet has been matched the chunk can be uninitialized.
 */
void 
rtp_packet_first_chunk_find(struct rtp_packet *pkt, struct rtp_packet_chunk *ret, int min_nsamples)
{

    assert(pkt->parsed->nsamples > min_nsamples);
    ret->whole_packet_matched = 0;

    switch (pkt->data.header.pt) {
    case RTP_PCMU:
    case RTP_PCMA:
	rtp_packet_chunk_find_g711(pkt, ret, min_nsamples);
	break;

    case RTP_G729:
	rtp_packet_chunk_find_g729(pkt, ret, min_nsamples);
	break;

    case RTP_GSM:
	rtp_packet_chunk_find_gsm(pkt, ret, min_nsamples);
	break;

    case RTP_G723:
	rtp_packet_chunk_find_g723(pkt, ret, min_nsamples);
	break;

    case RTP_G722:
	rtp_packet_chunk_find_g722(pkt, ret, min_nsamples);
	break;

    default:
	ret->whole_packet_matched = 1;
	break;
    }
}

const char *
rtp_packet_parse_errstr(rtp_parser_err_t ecode)
{
    switch (ecode) {
    case RTP_PARSER_OK:
       return "no error";

    case RTP_PARSER_PTOOSHRT:
       return "packet is too short for RTP header";

    case RTP_PARSER_IHDRVER:
       return "incorrect RTP header version";

    case RTP_PARSER_PTOOSHRTXS:
       return "packet is too short for extended RTP header size";

    case RTP_PARSER_PTOOSHRTXH:
       return "packet is too short for extended RTP header";

    case RTP_PARSER_PTOOSHRTPS:
        return "packet is too short for RTP padding size";

    case RTP_PARSER_PTOOSHRTP:
       return "packet is too short for RTP padding";

    case RTP_PARSER_IPS:
       return "invalid RTP padding size";

    default:
       abort();
    }

    /* NOTREACHED */
    return NULL;
}

rtp_parser_err_t
rtp_packet_parse_raw(unsigned char *buf, size_t size, struct rtp_info *rinfo)
{
    int padding_size;
    rtp_hdr_ext_t *hdr_ext_ptr;
    rtp_hdr_t *header;

    header = (rtp_hdr_t *)buf;

    padding_size = 0;

    rinfo->data_size = 0;
    rinfo->data_offset = 0;
    rinfo->appendable = 1;
    rinfo->nsamples = RTP_NSAMPLES_UNKNOWN;

    if (size < sizeof(*header))
        return RTP_PARSER_PTOOSHRT;

    if (header->version != 2)
        return RTP_PARSER_IHDRVER;

    rinfo->data_offset = RTP_HDR_LEN(header);

    if (header->x != 0) {
        if (size < rinfo->data_offset + sizeof(*hdr_ext_ptr))
            return RTP_PARSER_PTOOSHRTXS;
        hdr_ext_ptr = (rtp_hdr_ext_t *)&buf[rinfo->data_offset];
        rinfo->data_offset += sizeof(rtp_hdr_ext_t) +
          (ntohs(hdr_ext_ptr->length) * sizeof(hdr_ext_ptr->extension[0]));
    }

    if (size < rinfo->data_offset)
        return RTP_PARSER_PTOOSHRTXH;

    if (header->p != 0) {
        if (rinfo->data_offset == size)
            return RTP_PARSER_PTOOSHRTPS;
        padding_size = buf[size - 1];
        if (padding_size == 0)
            return RTP_PARSER_IPS;
    }

    if (size < rinfo->data_offset + padding_size)
        return RTP_PARSER_PTOOSHRTP;

    rinfo->data_size = size - rinfo->data_offset - padding_size;
    rinfo->ts = ntohl(header->ts);
    rinfo->seq = ntohs(header->seq);
    rinfo->ssrc = ntohl(header->ssrc);
    rinfo->rtp_profile = &rtp_profiles[header->pt];

    if (rinfo->data_size == 0)
        return RTP_PARSER_OK;

    rinfo->nsamples = rtp_calc_samples(header->pt, rinfo->data_size,
      &buf[rinfo->data_offset]);
    /* 
     * G.729 comfort noise frame as the last frame causes 
     * packet to be non-appendable
     */
    if (header->pt == RTP_G729 && (rinfo->data_size % 10) != 0)
        rinfo->appendable = 0;
    return RTP_PARSER_OK;
}

rtp_parser_err_t
rtp_packet_parse(struct rtp_packet *pkt)
{
    struct rtp_packet_full *pkt_full;
    struct rtp_info *rinfo;    

    if (pkt->parse_result != RTP_PARSER_NOTPARSED) {
        return (pkt->parse_result);
    }
    assert(pkt->parsed == NULL);
    pkt_full = (void *)pkt;
    rinfo = &(pkt_full->pvt.rinfo);
    pkt->parse_result = rtp_packet_parse_raw(pkt->data.buf, pkt->size, rinfo);
    if (pkt->parse_result == RTP_PARSER_OK) {
        pkt->parsed = rinfo;
    }
    return (pkt->parse_result);
}

void
rtp_packet_dup(struct rtp_packet *dpkt, const struct rtp_packet *spkt, int flags)
{
    int csize;
    struct rtp_packet_full *dpkt_full, *spkt_full;
    struct rtp_info *drinfo, *srinfo;

    csize = offsetof(struct rtp_packet, data.buf) + spkt->size;
    if ((flags & RTPP_DUP_HDRONLY) != 0) {
        assert(spkt->parse_result == RTP_PARSER_OK);
        csize -= spkt->parsed->data_size;
    }
    memcpy(dpkt, spkt, csize);
    if (dpkt->parsed == NULL) {
        return;
    }
    dpkt_full = (struct rtp_packet_full *)dpkt;
    drinfo = &(dpkt_full->pvt.rinfo);    
    spkt_full = (struct rtp_packet_full *)spkt;
    srinfo = &(spkt_full->pvt.rinfo);
    memcpy(drinfo, srinfo, sizeof(struct rtp_info));
    dpkt->parsed = drinfo;
    dpkt->wi = &(dpkt_full->pvt.wi);
    if ((flags & RTPP_DUP_HDRONLY) != 0) {
        dpkt->size -= dpkt->parsed->data_size;
        dpkt->parsed->data_size = 0;
        dpkt->parsed->nsamples = 0;
    }
}

struct rtp_packet *
rtp_packet_alloc()
{
    struct rtp_packet_full *pkt;

    pkt = rtpp_zmalloc(sizeof(*pkt));
    pkt->pub.wi = &pkt->pvt.wi;

    return &(pkt->pub);
}

void
rtp_packet_free(struct rtp_packet *pkt)
{

    free(pkt);
}

void 
rtp_packet_set_seq(struct rtp_packet *p, uint16_t seq)
{

    p->parsed->seq = seq;
    p->data.header.seq = htons(seq);
}

void 
rtp_packet_set_ts(struct rtp_packet *p, uint32_t ts)
{

    p->parsed->ts = ts;
    p->data.header.ts = htonl(ts);
}
