/*
 * Copyright (c) 2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id: rtp_resizer.c,v 1.1 2007/11/16 08:43:26 sobomax Exp $
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdint.h>

#include "rtp.h"
#include "rtp_resizer.h"

static int
min_nsamples(int codec_id)
{

    switch (codec_id)
    {
    case RTP_GSM:
        return 160; /* 20ms */
    case RTP_G723:
        return 240; /* 30ms */
    default:
        return 80;
    }
}

static int
max_nsamples(int codec_id)
{

    switch (codec_id)
    {
    case RTP_GSM:
        return 160; /* 20ms */
    default:
        return 0; /* infinite */
    }
}

void 
rtp_resizer_free(struct rtp_resizer *this)
{
    struct rtp_packet *p;
    struct rtp_packet *p1;

    p = this->queue.first;
    while (p != NULL) {
        p1 = p;
        p = p->next;
        rtp_packet_free(p1);
    }
}

void 
rtp_resizer_enqueue(struct rtp_resizer *this, struct rtp_packet **pkt)
{
    struct rtp_packet   *p;
    uint32_t            ref_ts, internal_ts;
    int                 delta;

    rtp_packet_parse(*pkt);

    if ((*pkt)->nsamples == RTP_NSAMPLES_UNKNOWN)
        return;

    (*pkt)->resizeable = 1;
    if ((*pkt)->header.pt == RTP_G729 && (*pkt)->data_size < 10) /* G.729 comfort noise frame */
        (*pkt)->resizeable = 0;

    if (this->last_sent_ts_inited && ts_less((*pkt)->ts, this->last_sent_ts))
    {
        /* Packet arrived too late. Drop it. */
        rtp_packet_free(*pkt);
        *pkt = NULL;
        return;
    }
    internal_ts = (*pkt)->rtime * 8000.0;
    if (!this->tsdelta_inited) {
        this->tsdelta = (*pkt)->ts - internal_ts + 40;
        this->tsdelta_inited = 1;
    }
    else {
        ref_ts = internal_ts + this->tsdelta;
        if (ts_less(ref_ts, (*pkt)->ts)) {
            this->tsdelta = (*pkt)->ts - internal_ts + 40;
/*            printf("Sync forward\n"); */
        }
        else if (ts_less((*pkt)->ts + this->output_nsamples + 160, ref_ts)) 
        {
            delta = (ref_ts - ((*pkt)->ts + this->output_nsamples + 160)) / 2;
            this->tsdelta -= delta;
/*            printf("Sync backward\n"); */
        }
    }
    if (this->queue.last != NULL) 
    {
        p = this->queue.last; 
        while (p != NULL && ts_less((*pkt)->ts, p->ts))
             p = p->prev;

        if (p == NULL) /* head reached */
        {
            (*pkt)->next = this->queue.first;
            (*pkt)->prev = NULL;
            this->queue.first->next = *pkt;
            this->queue.first = *pkt;
        }
        else if (p == this->queue.last) /* tail of the queue */
        {
            (*pkt)->prev = this->queue.last;
            (*pkt)->next = NULL;
            this->queue.last->next = *pkt;
            this->queue.last = *pkt;
        }
        else { /* middle of the queue */
            (*pkt)->next = p->next;
            (*pkt)->prev = p;
            (*pkt)->next->prev = (*pkt)->prev->next = *pkt;
        }
    }
    else {
        this->queue.first = this->queue.last = *pkt;
        (*pkt)->prev = NULL;
	(*pkt)->next = NULL;
    }
    this->nsamples_total += (*pkt)->nsamples;
    *pkt = NULL; /* take control over the packet */
}

struct rtp_packet *
rtp_resizer_get(struct rtp_resizer *this, double ctime)
{
    struct rtp_packet *ret = NULL;
    struct rtp_packet *p;
    uint32_t    ref_ts;
    int         count = 0;
    int         split = 0;
    int         nsamples_left;
    int         bytes_left;
    int         output_nsamples;
    int         max;

    if (this->queue.first == NULL)
        return NULL;

    ref_ts = (ctime * 8000.0) + this->tsdelta;

    /* Wait untill enough data has arrived or timeout occured */
    if (this->nsamples_total < this->output_nsamples &&
        ts_less(ref_ts, this->queue.first->ts + this->output_nsamples + 160))
    {
        return NULL;
    }

    max = max_nsamples(this->queue.first->header.pt);
    output_nsamples = this->output_nsamples - (this->output_nsamples % min_nsamples(this->queue.first->header.pt));

    if (output_nsamples == 0)
        output_nsamples = this->queue.first->nsamples;

    if (max > 0 && output_nsamples > max)
        output_nsamples = max;

    /* Aggregate the output packet */
    while ((ret == NULL || ret->nsamples < output_nsamples) && this->queue.first != NULL)
    {
        p = this->queue.first;
        if (ret == NULL) 
        {
            /* Look if the first packet is to be split */
            if (p->nsamples > output_nsamples && p->resizeable)
            {
                bytes_left = rtp_samples2bytes(p->header.pt, output_nsamples);
                if (bytes_left > 0) 
                {
                    ret = rtp_packet_alloc();
		    /* Copy only portion that is in use */
                    memcpy(ret, p, offsetof(struct rtp_packet, buf) + p->size);

                    ret->nsamples = output_nsamples;
                    ret->data_size = bytes_left;
                    ret->size = ret->data_offset + ret->data_size;

                    /* truncate the input packet */
                    p->nsamples -= output_nsamples;
                    rtp_packet_set_ts(p, p->ts + output_nsamples);
                    p->data_size -= bytes_left;
                    p->size -= bytes_left;
                    memmove(&p->buf[p->data_offset], &p->buf[p->data_offset + bytes_left], p->data_size);

                    this->nsamples_total -= output_nsamples;

                    ++split;
                    ++count;
                    break;
                }
            }
        }
        else /* ret != NULL */
        {
            /* Next packet is not resizeable, send current packet immediately */
            if (!p->resizeable)
                break;

            /* detect holes and payload changes in RTP stream */
            if ((ret->ts + ret->nsamples) != p->ts ||
                ret->header.pt != p->header.pt)
            {
                break;
            }
            nsamples_left = output_nsamples - ret->nsamples;

            /* Break the input packet into pieces to create output packet 
             * of specified size */
            if (nsamples_left > 0 && nsamples_left < p->nsamples && p->resizeable)
            {
                /* Take required number of bytes only */
                bytes_left = rtp_samples2bytes(ret->header.pt, nsamples_left);
                if (bytes_left > 0)
                {
                    memcpy(&ret->buf[ret->data_offset + ret->data_size], 
                            &p->buf[p->data_offset], bytes_left);
                    ret->nsamples += nsamples_left;
                    ret->data_size += bytes_left;
                    ret->size += bytes_left;

                    /* truncate the input packet */
                    p->nsamples -= nsamples_left;
                    rtp_packet_set_ts(p, p->ts + nsamples_left);
                    p->data_size -= bytes_left;
                    p->size -= bytes_left;
                    memmove(&p->buf[p->data_offset], &p->buf[p->data_offset + bytes_left], p->data_size);

                    this->nsamples_total -= nsamples_left;

                    ++split;
                    ++count;
                    break;
                }
            }
        }
        ++count;

        /*
         * Prevent RTP packet buffer overflow 
         */
        if (ret != NULL && (ret->size + p->data_size) > sizeof(ret->buf))
            break;

        /* Detach head packet from the queue */
        this->queue.first = p->next;
        if (p->next == NULL)
            this->queue.last = NULL;
        else
            p->next->prev = NULL;

        /*
         * Add the packet to the output
         */
        if (ret == NULL) {
            ret = p; /* use the first packet as the result container */
            this->nsamples_total -= p->nsamples;
            if (!this->seq_initialized) {
                this->seq = p->seq;
                this->seq_initialized = 1;
            }
            /* Send non-resizeable packet immediately */
            if (!ret->resizeable)
                break;
        }
        else {
            memcpy(&ret->buf[ret->data_offset + ret->data_size], 
                    &p->buf[p->data_offset], p->data_size);
            ret->nsamples += p->nsamples;
            ret->data_size += p->data_size;
            ret->size += p->data_size;
            this->nsamples_total -= p->nsamples;
            rtp_packet_free(p);
        }
    }
    rtp_packet_set_seq(ret, this->seq);
    ++this->seq;
    this->last_sent_ts_inited = 1;
    this->last_sent_ts = ret->ts + ret->nsamples;
/*
    printf("Payload %d, %d packets aggregated, %d splits done, final size %dms\n", ret->header.pt, count, split, ret->nsamples / 8);
*/
    return ret;
}
