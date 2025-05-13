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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "config_pp.h"

#include "rtpp_module.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_str.h"

#include "rtpp_dtls.h"
#include "rtpp_dtls_util.h"
#include "rtpp_dtls_conn.h"

struct rtpp_dtls_priv {
    struct rtpp_dtls pub;
    const struct rtpp_cfg *cfsp;
    struct rtpp_minfo *mself;
    SSL_CTX *ctx;
    X509 *cert;
    char fingerprint[FP_DIGEST_STRBUF_LEN];
};

static const char * const srtp_profiles =
  "SRTP_AES128_CM_SHA1_80:"
  "SRTP_AES128_CM_SHA1_32:"
  "SRTP_AEAD_AES_128_GCM:"
  "SRTP_AEAD_AES_256_GCM";

const char * const cn = "dtls@rtpproxy";
const char * const ecname = "prime256v1";

struct rtpp_dtls_conn *rtpp_dtls_newconn(struct rtpp_dtls *,
  struct rtpp_stream *);

static X509 *tls_set_selfsigned_ec(SSL_CTX *, const char *, const char *);
static void tls_set_verify_client(SSL_CTX *);

static void
rtpp_dtls_dtor(struct rtpp_dtls_priv *pvt)
{

    X509_free(pvt->cert);
    SSL_CTX_free(pvt->ctx);
}

struct rtpp_dtls *
rtpp_dtls_ctor(const struct rtpp_cfg *cfsp, struct rtpp_minfo *mself)
{
    struct rtpp_dtls_priv *pvt;

    pvt = mod_rzmalloc(sizeof(*pvt), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->ctx = SSL_CTX_new(DTLS_method());
    if (pvt->ctx == NULL) {
        ERR_clear_error();
        goto e1;
    }
    pvt->cert = tls_set_selfsigned_ec(pvt->ctx, cn, ecname);
    if (pvt->cert == NULL) {
        ERR_clear_error();
        goto e2;
    }
    tls_set_verify_client(pvt->ctx);
    if (SSL_CTX_set_tlsext_use_srtp(pvt->ctx, srtp_profiles) != 0) {
        ERR_clear_error();
        goto e3;
    }
    if (rtpp_dtls_fp_gen(pvt->cert, pvt->fingerprint,
      sizeof(pvt->fingerprint)) != 0) {
        goto e3;
    }
    pvt->pub.fingerprint = pvt->fingerprint;
    pvt->pub.newconn = &rtpp_dtls_newconn;
    pvt->cfsp = cfsp;
    pvt->mself = mself;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)rtpp_dtls_dtor, pvt);
    return (&(pvt->pub));
e3:
    X509_free(pvt->cert);
e2:
    SSL_CTX_free(pvt->ctx);
e1:
    mod_free(pvt);
e0:
    return (NULL);
}

struct rtpp_dtls_conn *
rtpp_dtls_newconn(struct rtpp_dtls *self, struct rtpp_stream *dtls_strmp)
{
    struct rtpp_dtls_priv *pvt;
    struct rtpp_dtls_conn *conn;

    PUB2PVT(self, pvt);

    conn = rtpp_dtls_conn_ctor(pvt->cfsp, pvt->ctx, dtls_strmp, pvt->mself);
    return (conn);
}

#ifndef OPENSSL_VERSION_MAJOR
#define OPENSSL_VERSION_MAJOR 1
#endif

static uint32_t
dtls_rand_u32(void)
{
    uint32_t v;

    v = 0;
    assert(RAND_bytes((unsigned char *)&v, sizeof(v)) == 1);
    return v;
}

static int
verify_trust_all(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;

    return 1;    /* We trust the certificate from peer */
}

static void
tls_set_verify_client(SSL_CTX *ctx)
{

    SSL_CTX_set_verify_depth(ctx, 0);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
      verify_trust_all);
}

static X509 *
tls_generate_cert(const char *cn)
{
    X509 *cert;
    X509_NAME *subj;

    cert = X509_new();
    if (!cert)
        goto e0;

    if (!X509_set_version(cert, 2))
        goto e1;

    if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), dtls_rand_u32()))
        goto e1;

    subj = X509_NAME_new();
    if (!subj)
        goto e1;

    if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
        (unsigned char *)cn, (int)strlen(cn), -1, 0))
        goto e2;

    if (!X509_set_issuer_name(cert, subj) ||
      !X509_set_subject_name(cert, subj))
        goto e2;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600*24*365) ||
      !X509_gmtime_adj(X509_getm_notAfter(cert),   3600*24*365*10))
        goto e2;
#else
    if (!X509_gmtime_adj(X509_get_notBefore(cert), -3600*24*365) ||
      !X509_gmtime_adj(X509_get_notAfter(cert),   3600*24*365*10))
        goto e2;
#endif

    X509_NAME_free(subj);
    return (cert);
e2:
    X509_NAME_free(subj);
e1:
    X509_free(cert);
e0:
    return (NULL);
}

static X509 *
tls_set_selfsigned_ec(SSL_CTX *ctx, const char *cn, const char *curve_n)
{
#if OPENSSL_VERSION_MAJOR < 3
    EC_KEY *eckey;
    int eccgrp;
#endif
    EVP_PKEY *key;
    X509 *cert;
    int r;

#if OPENSSL_VERSION_MAJOR >= 3
    key = EVP_EC_gen(curve_n);
    if (!key) {
        goto e0;
    }
#else
    key = EVP_PKEY_new();
    if (!key)
        goto e0;

    eccgrp = OBJ_txt2nid(curve_n);
    if (eccgrp == NID_undef)
        goto e1;

    eckey = EC_KEY_new_by_curve_name(eccgrp);
    if (!eckey)
        goto e1;

    if (!EC_KEY_generate_key(eckey))
        goto e2;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
#else
    EC_KEY_set_asn1_flag(eckey, 0);
#endif

    if (!EVP_PKEY_set1_EC_KEY(key, eckey))
        goto e2;
#endif /* OPENSSL_VERSION_MAJOR */

    cert = tls_generate_cert(cn);
    if (cert == NULL)
        goto e2;

    if (!X509_set_pubkey(cert, key))
        goto e3;

    if (!X509_sign(cert, key, EVP_sha256()))
        goto e3;

    r = SSL_CTX_use_certificate(ctx, cert);
    if (r != 1)
        goto e3;

    r = SSL_CTX_use_PrivateKey(ctx, key);
    if (r != 1)
        goto e3;

#if OPENSSL_VERSION_MAJOR < 3
    EC_KEY_free(eckey);
#endif
    EVP_PKEY_free(key);
    return cert;
e3:
    X509_free(cert);
e2:
#if OPENSSL_VERSION_MAJOR < 3
    EC_KEY_free(eckey);
e1:
#endif
    EVP_PKEY_free(key);
e0:
    return (NULL);
}
