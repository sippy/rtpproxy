/*
 * Copyright (c) 2017 Sippy Software, Inc., http://www.sippysoft.com
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

#include "sys/types.h"
#include "stdint.h"

struct udpip;

struct pcap_dissect {
    pcaprec_hdr_t pcaprec_hdr;
    int pcap_hdr_len;
    int l5_len;
    uint16_t dport;
    uint16_t sport;
    /* Points to unaligned data, use with caution! */
    struct udpip *udpip;
    struct in_addr *src;
    struct in_addr *dst;
    unsigned char *l5_data;
};

#define PCP_DSCT_OK   (0)
#define PCP_DSCT_UNKN (-1)
#define PCP_DSCT_TRNK (-2)

#define PCAP_REC_LEN(pdp) ((pdp)->pcap_hdr_len + (pdp)->l5_len)

int eaud_pcap_dissect(unsigned char *, size_t, int, struct pcap_dissect *);
