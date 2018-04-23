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

#ifndef _RTPP_WI_H_
#define _RTPP_WI_H_

struct rtpp_wi;
struct rtp_packet;
struct rtpp_refcnt;
struct sockaddr;
struct rtpp_netaddr;

enum rtpp_wi_type {RTPP_WI_TYPE_OPKT = 0, RTPP_WI_TYPE_SGNL = 1,
  RTPP_WI_TYPE_API_STR = 2, RTPP_WI_TYPE_DATA = 3};

struct rtpp_wi *rtpp_wi_malloc(int, const void *, size_t, int,
  const struct sockaddr *, size_t);
struct rtpp_wi *rtpp_wi_malloc_pkt(int, struct rtp_packet *,
  const struct sockaddr *, size_t, int, struct rtpp_refcnt *);
struct rtpp_wi *rtpp_wi_malloc_pkt_na(int, struct rtp_packet *,
  struct rtpp_netaddr *, int, struct rtpp_refcnt *);
enum rtpp_wi_type rtpp_wi_get_type(struct rtpp_wi *);
void *rtpp_wi_sgnl_get_data(struct rtpp_wi *, size_t *);
int rtpp_wi_sgnl_get_signum(struct rtpp_wi *);
struct rtpp_wi *rtpp_wi_malloc_apis(const char *, void *, size_t);
struct rtpp_wi *rtpp_wi_malloc_data(void *, size_t);
struct rtpp_wi *rtpp_wi_malloc_udata(void **, size_t);
void *rtpp_wi_data_get_ptr(struct rtpp_wi *, size_t, size_t);
const char *rtpp_wi_apis_getname(struct rtpp_wi *);
const char * rtpp_wi_apis_getnamearg(struct rtpp_wi *, void **, size_t);

void rtpp_wi_free(struct rtpp_wi *);

#if defined(RTPP_CHECK_LEAKS)
#define rtpp_wi_malloc_sgnl(args...) rtpp_wi_malloc_sgnl_memdeb(__FILE__, __LINE__, __func__, ## args)
struct rtpp_wi *rtpp_wi_malloc_sgnl_memdeb(const char *, int, const char *, int, const void *, size_t);
#else
struct rtpp_wi *rtpp_wi_malloc_sgnl(int, const void *, size_t);
#endif

#endif
