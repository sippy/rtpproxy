/*
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
 *
 *  Copyright (c) 2010-2016 <Alexandr Dubovikov>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the <SIPCAPTURE>. The name of the SIPCAPTURE may not be used to
 * endorse or promote products derived from this software without specific
 * prior written permission.

 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * Copyright (c) 2018 Maksym Sobolyev <sobomax@gmail.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
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
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

#define USE_IPV6
//#define USE_ZLIB

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#ifdef USE_ZLIB
#include <zlib.h>
#endif /* USE_ZLIB */

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif /* USE_SSL */  

#define HEP_VID_GEN	0x0000

#define HEP_TID_PF	0x0001	/* IP protocol family */
#define HEP_TID_PID	0x0002	/* IP protocol ID */
#define HEP_TID_SA4	0x0003	/* IPv4 source address */
#define HEP_TID_DA4	0x0004	/* IPv4 destination address */
#define HEP_TID_SA6	0x0005	/* IPv6 source address */
#define HEP_TID_DA6	0x0006	/* IPv6 destination address */
#define HEP_TID_SP	0x0007	/* protocol source port (UDP, TCP, SCTP) */
#define HEP_TID_DP	0x0008	/* protocol destination port (UDP, TCP, SCTP) */
#define HEP_TID_TS_S	0x0009	/* timestamp, seconds since 01/01/1970 (epoch) */
#define HEP_TID_TS_MS	0x000a	/* timestamp microseconds offset (added to timestamp) */
#define HEP_TID_PT	0x000b	/* protocol type (SIP/H323/RTP/MGCP/M2UA) */
#define HEP_TID_CAID	0x000c	/* capture agent ID (202, 1201, 2033...) */
		     /* 0x000d     keep alive timer (sec) */
#define HEP_TID_AKEY	0x000e	/* authenticate key (plain text / TLS connection) */
#define HEP_TID_PL_RAW	0x000f	/* captured uncompressed packet payload */
#define HEP_TID_PL_GZ	0x0010	/* captured compressed payload (gzip/inflate) */
#define HEP_TID_CID	0x0011	/* Internal correlation id */

#ifdef USE_SSL
SSL_CTX* initCTX(void);
#endif /* USE_SSL */

/* HEPv3 types */

struct hep_chunk {
       uint16_t vendor_id;
       uint16_t type_id;
       uint16_t length;
       uint8_t data[0];
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       uint8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       uint16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       uint32_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint32 hep_chunk_uint32_t;

struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} __attribute__((packed));

typedef struct hep_chunk_str hep_chunk_str_t;

struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip4 hep_chunk_ip4_t;

struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip6 hep_chunk_ip6_t;

struct hep_ctrl {
    char id[4];
    uint16_t length;
} __attribute__((packed));

typedef struct hep_ctrl hep_ctrl_t;

struct hep_chunk_payload {
    hep_chunk_t chunk;
    char *data;
} __attribute__((packed));

typedef struct hep_chunk_payload hep_chunk_payload_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

/*
static hep_generic_t HDR_HEP = {
    {0x48455033, 0x0},
    {0, 0x0001, 0x00, 0x00},
    {0, 0x0002, 0x00, 0x00},
    {0, 0x0003, 0x00, 0x00},
    {0, 0x0004, 0x00, 0x00},
    {0, 0x0005, 0x00, 0x00},
    {0, 0x0006, 0x00, 0x00},
    {0, 0x0007, 0x00, 0x00},
    {0, 0x0008, 0x00, 0x00},
    {0, 0x0009, 0x00, 0x00},
    {0, 0x000a, 0x00, 0x00},
    {0, 0x000b, 0x00, 0x00},
    {0, 0x000c, 0x00, 0x00},
    {0, 0x000d, 0x00, 0x00},
    {0, 0x000e, 0x00, 0x00},
    {0, 0x000f, 0x00, 0x00}
};
*/


struct hep_hdr{
    uint8_t hp_v;            /* version */
    uint8_t hp_l;            /* length */
    uint8_t hp_f;            /* family */
    uint8_t hp_p;            /* protocol */
    uint16_t hp_sport;       /* source port */
    uint16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
    uint32_t tv_sec;         /* seconds */
    uint32_t tv_usec;        /* useconds */
    uint16_t captid;         /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPV6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif
