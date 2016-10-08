/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

struct pollfd;
struct rtpp_session;
struct rtpp_sessinfo;
struct rtpp_socket;
struct rtpp_polltbl;
struct rtpp_weakref_obj;
struct rtpp_cfg_stable;

DEFINE_METHOD(rtpp_sessinfo, rtpp_si_append, int, struct rtpp_session *,
  int, struct rtpp_socket **);
DEFINE_METHOD(rtpp_sessinfo, rtpp_si_update, void, struct rtpp_session *,
  int, struct rtpp_socket **);
DEFINE_METHOD(rtpp_sessinfo, rtpp_si_remove, void, struct rtpp_session *,
  int);
DEFINE_METHOD(rtpp_sessinfo, rtpp_si_sync_polltbl, int, struct rtpp_polltbl *,
  int);

struct rtpp_polltbl_mdata;

struct rtpp_polltbl_mdata {
    uint64_t stuid;
    struct rtpp_socket *skt;
};

struct rtpp_polltbl {
    struct pollfd *pfds;
    struct rtpp_polltbl_mdata *mds;
    int curlen;
    int aloclen;
    uint64_t revision;
    struct rtpp_weakref_obj *streams_wrt;
};

struct rtpp_sessinfo {
    struct rtpp_refcnt *rcnt;
    METHOD_ENTRY(rtpp_si_append, append);
    METHOD_ENTRY(rtpp_si_update, update);
    METHOD_ENTRY(rtpp_si_remove, remove);
    METHOD_ENTRY(rtpp_si_sync_polltbl, sync_polltbl);
};

struct rtpp_sessinfo *rtpp_sessinfo_ctor(struct rtpp_cfg_stable *);

void rtpp_polltbl_free(struct rtpp_polltbl *);
