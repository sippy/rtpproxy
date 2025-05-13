/*
 * Copyright (c) 2022 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_refcnt;
struct rtpp_stream;
struct rtpp_dtls_conn;
struct rtp_packet;
struct pkt_proc_ctx;

enum rtpp_dtls_mode {
    RTPP_DTLS_MODERR  = -1,
    RTPP_DTLS_ACTPASS =  0,
    RTPP_DTLS_ACTIVE  =  1,
    RTPP_DTLS_PASSIVE =  2
};

struct rdc_peer_spec {
    enum rtpp_dtls_mode peer_mode;
    rtpp_str_const_t algorithm;
    const rtpp_str_t *fingerprint;
    const rtpp_str_t *ssrc;
    char alg_buf[FP_DIGEST_ALG_LEN];
};

struct res_loc {
    int v;
    here_t loc;
};
#define RES_HERE(res) (struct res_loc){(res), HEREVAL}

#if !defined(OPENSSL_VERSION_NUMBER)
typedef void SSL_CTX;
#endif
DECLARE_CLASS(rtpp_dtls_conn, const struct rtpp_cfg *,
  SSL_CTX *, struct rtpp_stream *, struct rtpp_minfo *);

DEFINE_METHOD(rtpp_dtls_conn, rtpp_dtls_conn_dtls_recv, void,
  const struct rtp_packet *);
DEFINE_METHOD(rtpp_dtls_conn, rtpp_dtls_conn_rtp_send, struct res_loc,
  struct pkt_proc_ctx *);
DEFINE_METHOD(rtpp_dtls_conn, rtpp_dtls_conn_srtp_recv, struct res_loc,
  struct pkt_proc_ctx *);
DEFINE_METHOD(rtpp_dtls_conn, rtpp_dtls_conn_setmode, enum rtpp_dtls_mode,
  const struct rdc_peer_spec *);
DEFINE_METHOD(rtpp_dtls_conn, rtpp_dtls_conn_godead, void);

DECLARE_SMETHODS(rtpp_dtls_conn)
{
    METHOD_ENTRY(rtpp_dtls_conn_dtls_recv, dtls_recv);
    METHOD_ENTRY(rtpp_dtls_conn_rtp_send, rtp_send);
    METHOD_ENTRY(rtpp_dtls_conn_srtp_recv, srtp_recv);
    METHOD_ENTRY(rtpp_dtls_conn_setmode, setmode);
    METHOD_ENTRY(rtpp_dtls_conn_godead, godead);
};

DECLARE_CLASS_PUBTYPE(rtpp_dtls_conn, {});
