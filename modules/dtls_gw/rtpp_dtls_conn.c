/*
 * Copyright (c) 2022 Sippy Software, Inc., http://www.sippysoft.com
 * Copyright (C) 2010 Alfred E. Heggestad
 * Copyright (C) 2010 Creytiv.com
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

#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/srtp.h>

#include <srtp2/srtp.h>

#include "config_pp.h"

#include "rtpp_module.h"
#include "rtpp_debug.h"
#include "rtpp_cfg.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_netio_async.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_str.h"
#include "rtpp_stream.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtp_packet.h"
#include "rtpp_packetops.h"
#include "rtpp_proc_async.h"
#include "rtpp_threads.h"
#include "rtpp_ssrc.h"
#include "rtpp_timed.h"
#include "rtpp_timed_task.h"
#include "rtpp_codeptr.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"
#include "rtpp_refproxy.h"
#include "rtpp_weakref.h"

#include "rtpp_dtls_util.h"
#include "rtpp_dtls_conn.h"

enum rdc_state {
    RDC_INIT,
    RDC_CONNECTING,
    RDC_UP,
    RDC_DEAD
};

enum srtp_suite {
    SRTP_AES_CM_128_HMAC_SHA1_32,
    SRTP_AES_CM_128_HMAC_SHA1_80,
    SRTP_F8_128_HMAC_SHA1_32,
    SRTP_F8_128_HMAC_SHA1_80,
    SRTP_AES_256_CM_HMAC_SHA1_32,
    SRTP_AES_256_CM_HMAC_SHA1_80,
    SRTP_AES_128_GCM,
    SRTP_AES_256_GCM,
};

DEFINE_RAW_METHOD(set_srtp_policy, void, srtp_crypto_policy_t *);

struct srtp_crypto_suite {
    const char *can_name;
    int key_size;
    int iv_size;
    int tag_size;
    srtp_sec_serv_t sec_serv;
    set_srtp_policy_t set_srtp_policy;
};

const struct srtp_crypto_suite srtp_suites [] = {
    [SRTP_AES_CM_128_HMAC_SHA1_32] = {.can_name = "AES_CM_128_HMAC_SHA1_32",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (128 / 8),
      .iv_size = (112 / 8), .tag_size = (32 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32},
    [SRTP_AES_CM_128_HMAC_SHA1_80] = {.can_name = "AES_CM_128_HMAC_SHA1_80",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (128 / 8),
      .iv_size = (112 / 8), .tag_size = (80 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_rtp_default},
    [SRTP_F8_128_HMAC_SHA1_32] = {.can_name = "F8_128_HMAC_SHA1_32",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (128 / 8),
      .iv_size = (112 / 8), .tag_size = (32 / 8)},
    [SRTP_F8_128_HMAC_SHA1_80] = {.can_name = "F8_128_HMAC_SHA1_80",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (128 / 8),
      .iv_size = (112 / 8), .tag_size = (80 / 8)},
    [SRTP_AES_256_CM_HMAC_SHA1_32] = {.can_name = "AES_256_CM_HMAC_SHA1_32",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (256 / 8),
      .iv_size = (112 / 8), .tag_size = (32 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32},
    [SRTP_AES_256_CM_HMAC_SHA1_80] = {.can_name = "AES_256_CM_HMAC_SHA1_80",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (256 / 8),
      .iv_size = (112 / 8), .tag_size = (80 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80},
    [SRTP_AES_128_GCM] = {.can_name = "AES_128_GCM",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (128 / 8),
      .iv_size = (96 / 8), .tag_size = (128 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_aes_gcm_128_16_auth},
    [SRTP_AES_256_GCM] = {.can_name = "AES_256_GCM",
      .sec_serv = sec_serv_conf_and_auth, .key_size = (256 / 8),
      .iv_size = (96 / 8), .tag_size = (128 / 8),
      .set_srtp_policy = srtp_crypto_policy_set_aes_gcm_256_16_auth}
};

struct rtpp_dtls_conn_priv {
    struct rtpp_dtls_conn pub;
    uint64_t dtls_strm_id;
    struct rtpp_timed *timed_cf;
    struct rtpp_weakref *streams_wrt;
    pthread_mutex_t state_lock;
    enum rdc_state state;
    enum rtpp_dtls_mode mode;
    SSL *ssl_ctx;
    srtp_t srtp_ctx_out;
    srtp_t srtp_ctx_in;
    BIO_METHOD *biomet;
    BIO *sbio_out;
    BIO *sbio_in;
    char fingerprint[FP_DIGEST_STRBUF_LEN];
    uint32_t ssrc;
    struct rtpp_timed_task *ttp;
    struct rtpp_minfo *mself;
};

static BIO_METHOD *bio_method_udp(void);
static int tls_accept(struct rtpp_dtls_conn_priv *);
static int tls_connect(struct rtpp_dtls_conn_priv *);
static int check_timer(struct rtpp_dtls_conn_priv *);

enum {
    MTU_DEFAULT  = 1400,
    MTU_FALLBACK = 548,
};

static void rtpp_dtls_conn_dtls_recv(struct rtpp_dtls_conn *,
  const struct rtp_packet *);
static struct res_loc rtpp_dtls_conn_rtp_send(struct rtpp_dtls_conn *,
  struct pkt_proc_ctx *);
static struct res_loc rtpp_dtls_conn_srtp_recv(struct rtpp_dtls_conn *,
  struct pkt_proc_ctx *);
static enum rtpp_dtls_mode rtpp_dtls_conn_setmode(struct rtpp_dtls_conn *,
  const struct rdc_peer_spec *rdfsp);
static void rtpp_dtls_conn_godead(struct rtpp_dtls_conn *);

static int tls_srtp_keyinfo(SSL *, const struct srtp_crypto_suite **,
  uint8_t *, size_t, uint8_t *, size_t, struct rtpp_log *);
static int tls_peer_fingerprint(SSL *, char *, size_t);

DEFINE_SMETHODS(rtpp_dtls_conn,
    .dtls_recv = &rtpp_dtls_conn_dtls_recv,
    .rtp_send = &rtpp_dtls_conn_rtp_send,
    .srtp_recv = &rtpp_dtls_conn_srtp_recv,
    .setmode = &rtpp_dtls_conn_setmode,
    .godead = &rtpp_dtls_conn_godead,
);

static void
rtpp_dtls_conn_dtor(struct rtpp_dtls_conn_priv *pvt)
{

    if (pvt->srtp_ctx_in != NULL)
        srtp_dealloc(pvt->srtp_ctx_in);
    if (pvt->srtp_ctx_out != NULL)
        srtp_dealloc(pvt->srtp_ctx_out);
    pthread_mutex_destroy(&pvt->state_lock);
    /* BIO_free(pvt->sbio_out); <- done by SSL_free() */
    /* BIO_free(pvt->sbio_in); <- done by SSL_free() */
    SSL_free(pvt->ssl_ctx);
    BIO_meth_free(pvt->biomet);
}

struct rtpp_dtls_conn *
rtpp_dtls_conn_ctor(const struct rtpp_cfg *cfsp, SSL_CTX *ctx,
  struct rtpp_stream *dtls_strmp, struct rtpp_minfo *mself)
{
    struct rtpp_dtls_conn_priv *pvt;

    pvt = mod_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->biomet = bio_method_udp();
    if (pvt->biomet == NULL) {
        ERR_clear_error();
        goto e1;
    }
    pvt->ssl_ctx = SSL_new(ctx);
    if (pvt->ssl_ctx == NULL) {
        ERR_clear_error();
        goto e2;
    }
    pvt->sbio_in = BIO_new(BIO_s_mem());
    if (pvt->sbio_in == NULL) {
        ERR_clear_error();
        goto e3;
    }
    pvt->sbio_out = BIO_new(pvt->biomet);
    if (pvt->sbio_out == NULL) {
        ERR_clear_error();
        goto e4;
    }
    if (pthread_mutex_init(&pvt->state_lock, NULL) != 0) {
        goto e5;
    }
    BIO_set_data(pvt->sbio_out, pvt);
    SSL_set_bio(pvt->ssl_ctx, pvt->sbio_in, pvt->sbio_out);
    SSL_set_read_ahead(pvt->ssl_ctx, 1);
    pvt->mode = RTPP_DTLS_ACTPASS;
    pvt->state = RDC_INIT;
    /* Cannot grab refcount here, circular reference would ensue */
    /* RTPP_OBJ_INCREF(dtls_strmp); */
    pvt->dtls_strm_id = dtls_strmp->stuid;
    RTPP_OBJ_BORROW(&pvt->pub, cfsp->rtp_streams_wrt);
    pvt->streams_wrt = cfsp->rtp_streams_wrt;
    pvt->timed_cf = cfsp->rtpp_timed_cf;
    PUBINST_FININIT(&pvt->pub, pvt, rtpp_dtls_conn_dtor);
    pvt->mself = mself;
    return (&(pvt->pub));
e5:
    BIO_free(pvt->sbio_out);
e4:
    BIO_free(pvt->sbio_in);
e3:
    SSL_free(pvt->ssl_ctx);
e2:
    BIO_meth_free(pvt->biomet);
e1:
    RTPP_OBJ_DECREF(&pvt->pub);
e0:
    return (NULL);
}

static enum rtpp_dtls_mode
rtpp_dtls_conn_pickmode(enum rtpp_dtls_mode peer_mode)
{

    switch (peer_mode) {
    case RTPP_DTLS_ACTPASS:
        return (RTPP_DTLS_PASSIVE);
    case RTPP_DTLS_ACTIVE:
        return (RTPP_DTLS_PASSIVE);
    case RTPP_DTLS_PASSIVE:
        return (RTPP_DTLS_ACTIVE);
    default:
        abort();
    }
    /* Not Reached */
}

static enum rtpp_dtls_mode
rtpp_dtls_conn_setmode(struct rtpp_dtls_conn *self,
  const struct rdc_peer_spec *rdfsp)
{
    struct rtpp_dtls_conn_priv *pvt;
    enum rtpp_dtls_mode my_mode;
    char *ep;

    PUB2PVT(self, pvt);

    pthread_mutex_lock(&pvt->state_lock);

    if (rdfsp == NULL) {
        goto out;
    }
    my_mode = rtpp_dtls_conn_pickmode(rdfsp->peer_mode);
    if (my_mode != pvt->mode && pvt->state != RDC_INIT) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "%p: cannot change mode "
          "from %d to %d when in the %d state", self, pvt->mode, my_mode,
          pvt->state);
        goto failed;
    }
    if (rdfsp->algorithm.len != FP_DIGEST_ALG_LEN ||
      memcmp(rdfsp->algorithm.s, FP_DIGEST_ALG, FP_DIGEST_ALG_LEN) != 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "unsupported fingerprint "
          "algorithm: \"%.*s\"", FMTSTR(&rdfsp->algorithm));
        goto failed;
    }
    if (rdfsp->fingerprint->len != FP_FINGERPRINT_STR_LEN) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "invalid fingerprint "
          "length: \"%lu\"", (unsigned long)rdfsp->fingerprint->len);
        goto failed;
    }
    sprintf(pvt->fingerprint, "%.*s %.*s", FMTSTR(&rdfsp->algorithm),
      FMTSTR(rdfsp->fingerprint));
    if (rdfsp->ssrc != NULL) {
        uint32_t ssrc = strtoul(rdfsp->ssrc->s, &ep, 10);
        if (ep == rdfsp->ssrc->s || ep[0] != '\0') {
            RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "invalid ssrc: %.*s",
              FMTSTR(rdfsp->ssrc));
            goto failed;
        }
        pvt->ssrc = ssrc;
    }
    if (my_mode == RTPP_DTLS_ACTIVE && pvt->state == RDC_INIT) {
        pvt->state = RDC_CONNECTING;
        if (tls_connect(pvt) != 0) {
            goto failed;
        }
    }
    pvt->mode = my_mode;
out:
    pthread_mutex_unlock(&pvt->state_lock);
    return (pvt->mode);
failed:
    pthread_mutex_unlock(&pvt->state_lock);
    return (RTPP_DTLS_MODERR);
}

static srtp_t
setup_srtp_stream(const struct srtp_crypto_suite *suite, uint8_t *key,
  uint32_t ssrc, struct rtpp_log *log)
{
    srtp_policy_t policy;
    srtp_t srtp_ctx;
    int err;

    memset(&policy, '\0', sizeof(policy));
    suite->set_srtp_policy(&policy.rtp);
    suite->set_srtp_policy(&policy.rtcp);
    policy.key = key;
    policy.window_size = 128;
    policy.rtp.auth_tag_len = suite->tag_size;
    policy.rtp.sec_serv = policy.rtcp.sec_serv = suite->sec_serv;

    if (ssrc == SSRC_BAD) {
        policy.ssrc.type  = ssrc_any_inbound;
    } else {
        policy.ssrc.type  = ssrc_specific;
        policy.ssrc.value = ssrc;
    }

    err = srtp_create(&srtp_ctx, &policy);
    if (err != srtp_err_status_ok || srtp_ctx == NULL) {
        RTPP_LOG(log, RTPP_LOG_ERR, "srtp_create() failed");
        return (NULL);
    }
    return (srtp_ctx);
}

static void
rtpp_dtls_conn_dtls_recv(struct rtpp_dtls_conn *self,
  const struct rtp_packet *pktp)
{
    struct rtpp_dtls_conn_priv *pvt;
    int r, err;
    uint8_t cli_key[32+14], srv_key[32+14];
    const struct srtp_crypto_suite *suite;
    char srv_fingerprint[FP_DIGEST_STRBUF_LEN];

    PUB2PVT(self, pvt);

    pthread_mutex_lock(&pvt->state_lock);

    switch (pvt->state) {
    case RDC_INIT:
        pvt->state = RDC_CONNECTING;
        break;
    case RDC_CONNECTING:
    case RDC_UP:
        break;
    case RDC_DEAD:
        goto out;
    }

    r = BIO_write(pvt->sbio_in, pktp->data.buf, pktp->size);
    if (r <= 0) {
        RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "receive bio write error: %i", r);
        ERR_clear_error();
        goto out;
    }
    if (SSL_get_state(pvt->ssl_ctx) != TLS_ST_OK) {
        if (pvt->state == RDC_UP) {
            goto godead;
        }
        if (pvt->mode == RTPP_DTLS_ACTIVE)
            err = tls_connect(pvt);
        else
            err = tls_accept(pvt);
        if (err) {
            goto godead;
        }

#if 0
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "%s: state=0x%04x",
          "server", SSL_get_state(pvt->ssl_ctx));
#endif

        /* TLS connection is established */
        if (SSL_get_state(pvt->ssl_ctx) != TLS_ST_OK)
            goto out;

        err = tls_srtp_keyinfo(pvt->ssl_ctx, &suite, cli_key, sizeof(cli_key),
          srv_key, sizeof(srv_key), pvt->mself->log);
        if (err != 0) {
            goto godead;
        }

        err = tls_peer_fingerprint(pvt->ssl_ctx, srv_fingerprint,
          sizeof(srv_fingerprint));
        if (err != 0) {
            goto godead;
        }

        if (pvt->fingerprint[0] != '\0' &&
          strcmp(pvt->fingerprint, srv_fingerprint) != 0) {
            RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "fingerprint verification failed");
            goto godead;
        }

        pvt->srtp_ctx_out = setup_srtp_stream(suite,
          pvt->mode == RTPP_DTLS_ACTIVE ? cli_key : srv_key, SSRC_BAD,
          pvt->mself->log);
        if (pvt->srtp_ctx_out == NULL) {
            goto godead;
        }
        pvt->srtp_ctx_in = setup_srtp_stream(suite,
          pvt->mode == RTPP_DTLS_ACTIVE ? srv_key : cli_key, pvt->ssrc,
          pvt->mself->log);
        if (pvt->srtp_ctx_in == NULL) {
            goto godead;
        }

#if 0
        RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG,
          "DTLS connection is established with %s key: %s", suite->can_name,
            pvt->fingerprint);
#endif
        pvt->state = RDC_UP;
    }
    goto out;
godead:
    RTPP_LOG(pvt->mself->log, RTPP_LOG_DBUG, "DTLS connection is dead: %p",
      pvt);
    pvt->state = RDC_DEAD;
out:
    pthread_mutex_unlock(&pvt->state_lock);
}

#if SRTP_PROTECT_NARGS == 4
#define SRTP_PROTECT(a, b, c) srtp_protect(a, b, c, 0)
#define SRTCP_PROTECT(a, b, c) srtp_protect_rtcp(a, b, c, 0)
#else
#define SRTP_PROTECT(a, b, c) srtp_protect(a, b, c)
#define SRTCP_PROTECT(a, b, c) srtp_protect_rtcp(a, b, c)
#endif

static struct res_loc
rtpp_dtls_conn_rtp_send(struct rtpp_dtls_conn *self, struct pkt_proc_ctx *pktxp)
{
    struct res_loc status;
#if defined(SRTP_PROTECT_LASTARG)
    SRTP_PROTECT_LASTARG len;
#else
    size_t len;
#endif
    struct rtpp_dtls_conn_priv *pvt;

    PUB2PVT(self, pvt);

    if (pvt->state != RDC_UP) {
        return (RES_HERE(-1));
    }

    len = pktxp->pktp->size;
    if (rtpp_is_rtcp_tst(pktxp)) {
        status = RES_HERE(SRTCP_PROTECT(pvt->srtp_ctx_out, pktxp->pktp->data.buf, &len));
    } else {
        status = RES_HERE(SRTP_PROTECT(pvt->srtp_ctx_out, pktxp->pktp->data.buf, &len));
    }
    if (status.v) {
        status.v = -1;
        return (status);
    }
    pktxp->pktp->size = len;
    CALL_SMETHOD(pktxp->strmp_in->pproc_manager, handleat, pktxp,
      PPROC_ORD_ENCRYPT + 1);
    return (RES_HERE(0));
}

static struct res_loc
rtpp_dtls_conn_srtp_recv(struct rtpp_dtls_conn *self, struct pkt_proc_ctx *pktxp)
{
    struct res_loc status;
#if defined(SRTP_PROTECT_LASTARG)
    SRTP_PROTECT_LASTARG len;
#else
    size_t len;
#endif
    struct rtpp_dtls_conn_priv *pvt;

    PUB2PVT(self, pvt);

    if (pvt->state != RDC_UP) {
        return (RES_HERE(-1));
    }

    len = pktxp->pktp->size;
    if (rtpp_is_rtcp_tst(pktxp)) {
        status = RES_HERE(srtp_unprotect_rtcp(pvt->srtp_ctx_in, pktxp->pktp->data.buf, &len));
    } else {
        status = RES_HERE(srtp_unprotect(pvt->srtp_ctx_in, pktxp->pktp->data.buf, &len));
    }
    if (status.v) {
        status.v = -1;
        return (status);
    }
    pktxp->pktp->size = len;
    CALL_SMETHOD(pktxp->strmp_in->pproc_manager, handleat, pktxp,
      PPROC_ORD_DECRYPT + 1);
    return (RES_HERE(0));
}

static int
bio_write(BIO *b, const char *buf, int len)
{
    struct rtpp_dtls_conn_priv *pvt = BIO_get_data(b);
    struct rtp_packet *packet;
    struct rtpp_stream *dtls_strmp;

    dtls_strmp = CALL_SMETHOD(pvt->streams_wrt, get_by_idx, pvt->dtls_strm_id);
    if (dtls_strmp == NULL)
        goto e0;
    if (len > MAX_RPKT_LEN || !CALL_SMETHOD(dtls_strmp, issendable))
        goto e1;
    packet = rtp_packet_alloc();
    if (packet == NULL)
        goto e1;
    memcpy(packet->data.buf, buf, len);
    packet->size = len;
    CALL_SMETHOD(dtls_strmp, send_pkt, NULL, packet);
    RTPP_OBJ_DECREF(dtls_strmp);
    return (len);
e1:
    RTPP_OBJ_DECREF(dtls_strmp);
e0:
    return (-1);
}

static long
bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;

    switch (cmd) {

    case BIO_CTRL_FLUSH:
        /* The OpenSSL library needs this */
        return 1;

#if defined (BIO_CTRL_DGRAM_QUERY_MTU)
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return MTU_DEFAULT;
#endif

#if defined (BIO_CTRL_DGRAM_GET_FALLBACK_MTU)
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        return MTU_FALLBACK;
#endif
    }

    return 0;
}

static int
bio_create(BIO *b)
{
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);

    return (1);
}


static int
bio_destroy(BIO *b)
{

    BIO_set_init(b, 0);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);

    return (1);
}

static BIO_METHOD *
bio_method_udp(void)
{
    BIO_METHOD *method;

    method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "udp_send");
    if (!method) {
        return NULL;
    }

    BIO_meth_set_write(method, bio_write);
    BIO_meth_set_ctrl(method, bio_ctrl);
    BIO_meth_set_create(method, bio_create);
    BIO_meth_set_destroy(method, bio_destroy);

    return (method);
}

static int
tls_print_error(const char *str, size_t len, void *arg)
{
    struct rtpp_log *log = arg;
    RTPP_LOG(log, RTPP_LOG_ERR, "%.*s", (int)len, str);

    return 1;
}


static void
tls_flush_error(struct rtpp_log *log)
{

    ERR_print_errors_cb(tls_print_error, log);
}

static int
tls_accept(struct rtpp_dtls_conn_priv *pvt)
{
    int r;

    RTPP_DBG_ASSERT(rtpp_mutex_islocked(&pvt->state_lock));

    ERR_clear_error();

    r = SSL_accept(pvt->ssl_ctx);
    if (r <= 0) {
        const int ssl_err = SSL_get_error(pvt->ssl_ctx, r);

        tls_flush_error(pvt->mself->log);

        switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            break;

        default:
            RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "accept error: %i",
              ssl_err);
            return (-1);
        }
    }

    if (check_timer(pvt) != 0)
        return (-1);

    return (0);
}

static enum rtpp_timed_cb_rvals
rtpp_dtls_conn_timeout(double dtime, void *arg)
{
    struct rtpp_dtls_conn_priv *pvt = arg;

    pthread_mutex_lock(&pvt->state_lock);

    if (pvt->ttp == NULL) {
        /* Lost race with check_timer() */
        goto done;
    }

    RTPP_OBJ_DECREF(pvt->ttp);
    pvt->ttp = NULL;
    if (pvt->state != RDC_CONNECTING)
        goto done;
    if (DTLSv1_handle_timeout(pvt->ssl_ctx) >= 0) {
        if (check_timer(pvt) != 0)
            pvt->state = RDC_DEAD;
    } else {
        ERR_clear_error();
        pvt->state = RDC_DEAD;
    }
done:
    pthread_mutex_unlock(&pvt->state_lock);
    return (CB_LAST);
}

static int
check_timer(struct rtpp_dtls_conn_priv *pvt)
{
    int err;
    struct timeval tv = {0, 0};

    RTPP_DBG_ASSERT(rtpp_mutex_islocked(&pvt->state_lock));

    err = DTLSv1_get_timeout(pvt->ssl_ctx, &tv);
    if (err == 1 && pvt->ttp != NULL)
        return (0);
    if (err == 1) {
        double to = timeval2dtime(&tv);
        pvt->ttp = CALL_SMETHOD(pvt->timed_cf, schedule_rc, to,
          pvt->pub.rcnt, rtpp_dtls_conn_timeout, NULL, pvt);
        if (pvt->ttp == NULL)
            return (-1);
    } else if (pvt->ttp != NULL) {
        CALL_METHOD(pvt->ttp, cancel);
        RTPP_OBJ_DECREF(pvt->ttp);
        pvt->ttp = NULL;
    }

    return (0);
}

static int
tls_connect(struct rtpp_dtls_conn_priv *pvt)
{
    int r;

    RTPP_DBG_ASSERT(rtpp_mutex_islocked(&pvt->state_lock));

    ERR_clear_error();

    r = SSL_connect(pvt->ssl_ctx);
    if (r <= 0) {
        const int ssl_err = SSL_get_error(pvt->ssl_ctx, r);

        tls_flush_error(pvt->mself->log);

        switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            break;

        default:
            RTPP_LOG(pvt->mself->log, RTPP_LOG_ERR, "connect error: %i",
              ssl_err);
            return (-1);
        }
    }

    check_timer(pvt);

    return (0);
}

static void
mem_secclean(void *data, size_t size)
{
    memset(data, 0, size);
    /* Insert an asm statement that may potentially depend
     * on the memory contents that were affected by memset.
     * This prevents optimizing away the memset. */
    __asm__ __volatile__("" : : "r" (data), "r" (size) : "memory");
}

static int
tls_srtp_keyinfo(SSL *ssl_ctx, const struct srtp_crypto_suite **suite,
  uint8_t *cli_key, size_t cli_key_size, uint8_t *srv_key,
  size_t srv_key_size, struct rtpp_log *log)
{
    static const char *label = "EXTRACTOR-dtls_srtp";
    size_t size;
    SRTP_PROTECTION_PROFILE *sel;
    uint8_t keymat[256], *p;

    sel = SSL_get_selected_srtp_profile(ssl_ctx);
    if (!sel) {
        ERR_clear_error();
        RTPP_LOG(log, RTPP_LOG_ERR,
          "SSL_get_selected_srtp_profile() failed");
        return (-1);
    }

    switch (sel->id) {
    case SRTP_AES128_CM_SHA1_80:
        *suite = &srtp_suites[SRTP_AES_CM_128_HMAC_SHA1_80];
        break;

    case SRTP_AES128_CM_SHA1_32:
        *suite = &srtp_suites[SRTP_AES_CM_128_HMAC_SHA1_32];
        break;

    case SRTP_AES128_F8_SHA1_80:
        *suite = &srtp_suites[SRTP_F8_128_HMAC_SHA1_80];
        break;

    case SRTP_AES128_F8_SHA1_32:
        *suite = &srtp_suites[SRTP_F8_128_HMAC_SHA1_32];
        break;

#ifdef SRTP_AEAD_AES_128_GCM
    case SRTP_AEAD_AES_128_GCM:
        *suite = &srtp_suites[SRTP_AES_128_GCM];
        break;
#endif

#ifdef SRTP_AEAD_AES_256_GCM
    case SRTP_AEAD_AES_256_GCM:
        *suite = &srtp_suites[SRTP_AES_256_GCM];
        break;
#endif

    default:
        abort();
    }

    size = (*suite)->key_size + (*suite)->iv_size;

    if (cli_key_size < size || srv_key_size < size)
        abort();

    if (sizeof(keymat) < (2 * size))
        abort();

    if (SSL_export_keying_material(ssl_ctx, keymat, 2 * size, label,
      strlen(label), NULL, 0, 0) != 1) {
        ERR_clear_error();
        RTPP_LOG(log, RTPP_LOG_ERR,
          "SSL_export_keying_material() failed");
        return (-1);
    }

    p = keymat;

    memcpy(cli_key, p, (*suite)->key_size);
    p += (*suite)->key_size;
    memcpy(srv_key, p, (*suite)->key_size);
    p += (*suite)->key_size;
    memcpy(cli_key + (*suite)->key_size, p, (*suite)->iv_size);
    p += (*suite)->iv_size;
    memcpy(srv_key + (*suite)->key_size, p, (*suite)->iv_size);

    mem_secclean(keymat, sizeof(keymat));

    return (0);
}

static int
tls_peer_fingerprint(SSL *ssl_ctx, char *buf, size_t size)
{
    X509 *cert;
    int err;

    cert = SSL_get_peer_certificate(ssl_ctx);
    if (cert == NULL)
        return (-1);

    err = rtpp_dtls_fp_gen(cert, buf, size);

    X509_free(cert);

    return (err);
}

static void
rtpp_dtls_conn_godead(struct rtpp_dtls_conn *self)
{
    struct rtpp_dtls_conn_priv *pvt;

    PUB2PVT(self, pvt);

    pthread_mutex_lock(&pvt->state_lock);
    pvt->state = RDC_DEAD;
    if (pvt->ttp != NULL) {
        CALL_METHOD(pvt->ttp, cancel);
        RTPP_OBJ_DECREF(pvt->ttp);
        pvt->ttp = NULL;
    }
    pthread_mutex_unlock(&pvt->state_lock);
}
