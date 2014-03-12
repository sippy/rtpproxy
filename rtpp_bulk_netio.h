/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_BULK_NETIO_H_
#define _RTPP_BULK_NETIO_H_

struct rtpp_bnet_opipe;
struct rtpp_bnet_ipipe;

typedef void (*ipipe_cb_t) (struct rtp_packet *, void *);

struct rtpp_bnet_opipe *rtpp_bulk_netio_opipe_new(int, int, int);
int rtpp_bulk_netio_opipe_destroy(struct rtpp_bnet_opipe *);
int rtpp_bulk_netio_opipe_flush(struct rtpp_bnet_opipe *);
int rtpp_bulk_netio_opipe_sendto(struct rtpp_bnet_opipe *, int, const void *, \
  size_t, int, const struct sockaddr *, socklen_t);
int rtpp_bulk_netio_opipe_send_pkt(struct rtpp_bnet_opipe *, int, \
  const struct sockaddr *, socklen_t, struct rtp_packet *);

struct rtpp_bnet_ipipe *rtpp_bulk_netio_ipipe_new(int);
int rtpp_bulk_netio_ipipe_add_s(struct rtpp_bnet_ipipe *, int, \
  int, void *);
void rtpp_bulk_netio_ipipe_pump(struct rtpp_bnet_ipipe *, ipipe_cb_t);
void rtpp_bulk_netio_ipipe_reset(struct rtpp_bnet_ipipe *);
void rtpp_bulk_netio_ipipe_destroy(struct rtpp_bnet_ipipe *);

int rtpp_bulk_netio_init();

#endif
