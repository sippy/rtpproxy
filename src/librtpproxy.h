/*
 * Copyright (c) 2023-2026 Sippy Software, Inc., http://www.sippysoft.com
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

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*rtp_packet_ext_dtor_t)(void *);

struct rtpp_cfg;
struct SPMCQueue;

void rtpp_shutdown(struct rtpp_cfg *);
struct rtpp_cfg *rtpp_main(int argc, const char * const *argv);

struct rtpp_packetport {
    struct SPMCQueue *in;
    struct SPMCQueue *out;
};

struct rtp_packet_ext {
    const void *data;
    int dlen;
    unsigned int port;
};

struct rtpp_packetport *rtpp_packetport_ctor(unsigned int);
void rtpp_packetport_push(struct rtpp_packetport *, struct rtp_packet_ext *);
int rtpp_packetport_try_push(struct rtpp_packetport *, struct rtp_packet_ext *);
struct rtp_packet_ext *rtpp_packetport_try_pop(struct rtpp_packetport *);
size_t rtpp_packetport_try_pop_many(struct rtpp_packetport *,
  struct rtp_packet_ext **, size_t);
unsigned int rtpp_packetport_next_in_port(struct rtpp_packetport *);
void rtpp_packetport_dtor(struct rtpp_packetport *);
struct rtp_packet_ext *rtp_packet_ext_ctor(int, unsigned int, const void *,
  rtp_packet_ext_dtor_t, void *);
void rtp_packet_ext_dtor(struct rtp_packet_ext *);

#ifdef __cplusplus
}
#endif
