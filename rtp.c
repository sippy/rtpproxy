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
 * $Id: rtp.c,v 1.3 2007/11/16 01:58:58 sobomax Exp $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "rtp.h"
#include "rtpp_util.h"

/* Linked list of free packets */
static struct rtp_packet *rtp_packet_pool = NULL;

struct rtp_packet *
rtp_packet_alloc()
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_pool;
    if (pkt != NULL)
        rtp_packet_pool = pkt->next;
    else
        pkt = malloc(sizeof(*pkt));
    memset(pkt, 0, sizeof(*pkt));
    pkt->rlen = sizeof(pkt->raddr);
    return pkt;
}

void
rtp_packet_free(struct rtp_packet *pkt)
{
    pkt->next = rtp_packet_pool;
    rtp_packet_pool = pkt;
}

struct rtp_packet *
rtp_recv(int fd)
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_alloc();

    if (pkt == NULL)
        return NULL;

    pkt->size = recvfrom(fd, pkt->buf, sizeof(pkt->buf), 0, 
      sstosa(&pkt->raddr), &pkt->rlen);

    if (pkt->size == -1) {
	rtp_packet_free(pkt);
	return NULL;
    }
    
    return pkt;
}
