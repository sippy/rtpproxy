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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <string.h>

#include "rtpp_record_private.h"
#include "eaud_pcap.h"

static uint16_t
ntohsp(unsigned char *np)
{
    uint16_t portnum;

    memcpy(&portnum, np, sizeof(portnum));
    return (ntohs(portnum));
}

int
eaud_pcap_dissect(unsigned char *bp, size_t blen, int network,
  struct pcap_dissect *dp)
{
    union pkt_hdr_pcap *pcp;
    uint32_t incl_len;

    pcp = (union pkt_hdr_pcap *)bp;
    memset(dp, '\0', sizeof(*dp));
    if (network == DLT_NULL) {
        uint32_t family;

        if (blen < sizeof(pcp->null)) {
            return (PCP_DSCT_TRNK);
        }
        memcpy(&family, &pcp->null.family, sizeof(family));
        memcpy(&incl_len, &pcp->null.pcaprec_hdr.incl_len, sizeof(incl_len));
        if (family != AF_INET) {
            dp->pcap_hdr_len = sizeof(pcaprec_hdr_t) + incl_len;
            return (PCP_DSCT_UNKN);
        }
        memcpy(&dp->pcaprec_hdr, &pcp->null.pcaprec_hdr, sizeof(pcaprec_hdr_t));
        dp->pcap_hdr_len = sizeof(struct pkt_hdr_pcap_null);
        dp->udpip = &(pcp->null.udpip);
    } else {
        uint16_t ether_type;

        if (blen < sizeof(pcp->en10t)) {
            return (PCP_DSCT_TRNK);
        }
        memcpy(&ether_type, &pcp->en10t.ether.type, sizeof(ether_type));
        memcpy(&incl_len, &pcp->en10t.pcaprec_hdr.incl_len, sizeof(incl_len));
        if (ether_type != ETHERTYPE_INET) {
            dp->pcap_hdr_len = sizeof(pcaprec_hdr_t) + incl_len;
            return (PCP_DSCT_UNKN);
        }
        memcpy(&dp->pcaprec_hdr, &pcp->en10t.pcaprec_hdr, sizeof(pcaprec_hdr_t));
        dp->pcap_hdr_len = sizeof(struct pkt_hdr_pcap_en10t);
        dp->udpip = &(pcp->en10t.udpip);
    }
    dp->l5_len = incl_len + sizeof(pcaprec_hdr_t) - dp->pcap_hdr_len;
    if (dp->l5_len < 0) {
        return (PCP_DSCT_TRNK);
    }
    dp->l5_data = (unsigned char *)(dp->udpip + 1);
    dp->src = &dp->udpip->iphdr.ip_src;
    dp->sport = ntohsp((void *)&dp->udpip->udphdr.uh_sport);
    dp->dst = &dp->udpip->iphdr.ip_dst;
    dp->dport = ntohsp((void *)&dp->udpip->udphdr.uh_dport);
    return (PCP_DSCT_OK);
}
