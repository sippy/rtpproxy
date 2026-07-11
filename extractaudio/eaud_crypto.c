/*
 * Copyright (c) 2016 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#include <netinet/in.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#if ENABLE_SRTP
#	include <srtp/srtp.h>
#	define srtp_crypto_policy_set_rtp_default crypto_policy_set_rtp_default
#	define srtp_crypto_policy_set_rtcp_default crypto_policy_set_rtcp_default
#	define srtp_sec_serv_t sec_serv_t
#	define srtp_err_status_ok err_status_ok
#elif ENABLE_SRTP2
#	include <srtp2/srtp.h>
#else
#	error "One of srtp or srtp2 must be configured."
#endif

/* XXX: srtp.h defines those, undef to avoid warnings */
#undef PACKAGE
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION

#include "rtpp_endian.h"
#include "rtp.h"
#include "rtp_info.h"
#include "eaud_crypto.h"
#include "srtp_util.h"

/*
 * Master-key + salt octet counts, per RFC 3711 (CM ciphers) and RFC 7714
 * (GCM/AEAD ciphers). These mirror SRTP_SALT_LEN (14), SRTP_AEAD_SALT_LEN
 * (12), and SRTP_AES_{128,192,256}_KEY_LEN from <srtp2/srtp.h>, spelled
 * out here so this table is self-contained and doesn't depend on
 * internal libsrtp2 macros that may not exist in older libsrtp (v1).
 */
#define CM_SALT_LEN     14
#define AEAD_SALT_LEN   12
#define AES_128_KEY_LEN 16
#define AES_192_KEY_LEN 24
#define AES_256_KEY_LEN 32

typedef void (*srtp_policy_setter_t)(srtp_crypto_policy_t *);

struct srtp_crypto_suite {
    const char *can_name;
    int ckey_len;                     /* total master key + salt, in octets */
    srtp_policy_setter_t set_policy;  /* configures both cipher & auth      */
};

#define MAX_KEY_LEN      96

struct eaud_crypto {
    const struct srtp_crypto_suite *suite;
    srtp_policy_t policy;
    srtp_t srtp_ctx;
    char key[MAX_KEY_LEN];
};

/*
 * Each entry's set_policy is called directly against both the .rtp and
 * .rtcp fields of srtp_policy_t (which share the same srtp_crypto_policy_t
 * type), so cipher type, key length, auth type/tag length and sec_serv are
 * all configured consistently by libsrtp2 itself instead of being
 * reconstructed by hand here.
 */
static struct srtp_crypto_suite srtp_crypto_suites[] = {
    {.can_name = "AES_CM_128_HMAC_SHA1_32",
     .ckey_len = AES_128_KEY_LEN + CM_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32},
    {.can_name = "AES_CM_128_HMAC_SHA1_80",
     .ckey_len = AES_128_KEY_LEN + CM_SALT_LEN,
     /* srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80() is a macro alias
      * for this in <srtp2/srtp.h>, not a real function -- can't take
      * its address, so reference the underlying function directly. */
     .set_policy = srtp_crypto_policy_set_rtp_default},
    {.can_name = "AES_192_CM_HMAC_SHA1_32",
     .ckey_len = AES_192_KEY_LEN + CM_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32},
    {.can_name = "AES_192_CM_HMAC_SHA1_80",
     .ckey_len = AES_192_KEY_LEN + CM_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80},
    {.can_name = "AES_256_CM_HMAC_SHA1_32",
     .ckey_len = AES_256_KEY_LEN + CM_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32},
    {.can_name = "AES_256_CM_HMAC_SHA1_80",
     .ckey_len = AES_256_KEY_LEN + CM_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80},
#if ENABLE_SRTP2
    {.can_name = "AEAD_AES_128_GCM_8",
     .ckey_len = AES_128_KEY_LEN + AEAD_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_gcm_128_8_auth},
    {.can_name = "AEAD_AES_128_GCM",
     .ckey_len = AES_128_KEY_LEN + AEAD_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_gcm_128_16_auth},
    {.can_name = "AEAD_AES_256_GCM_8",
     .ckey_len = AES_256_KEY_LEN + AEAD_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_gcm_256_8_auth},
    {.can_name = "AEAD_AES_256_GCM",
     .ckey_len = AES_256_KEY_LEN + AEAD_SALT_LEN,
     .set_policy = srtp_crypto_policy_set_aes_gcm_256_16_auth},
#endif
    {.can_name = NULL}
};

static struct srtp_crypto_suite *
srtp_crypto_suite_lookup(const char *suite_name, int name_len)
{
    struct srtp_crypto_suite *i_scsp;;

    for (i_scsp = &srtp_crypto_suites[0]; i_scsp->can_name != NULL; i_scsp++) {
        if (strlen(i_scsp->can_name) != name_len) {
            continue;
        }
        if (strncasecmp(i_scsp->can_name, suite_name, name_len) == 0) {
            return (i_scsp);
        }
    }
    return (NULL);
}

struct eaud_crypto *
eaud_crypto_getopt_parse(char *optarg)
{
    struct eaud_crypto *rval;
    struct srtp_crypto_suite *suite;
    char *dlm, *skey;;
    int expected_len, pad, len;

    dlm = strchr(optarg, ':');
    if (dlm == NULL) {
        fprintf(stderr, "invalid crypto argument must be in the format "
          "\"<suite>:<base64_key>\": %s\n", optarg);
        return (NULL);
    }
    suite = srtp_crypto_suite_lookup(optarg, dlm - optarg);
    if (suite == NULL) {
        fprintf(stderr, "unknown or unsupported crypto suite: %.*s\n",
          (int)(dlm - optarg), optarg);
        return (NULL);
    }
    /*
     * Standard (padded) base64 length for suite->ckey_len octets:
     * ceil(ckey_len / 3) * 4. This must use ceiling division, not the
     * simple "* 4 / 3" truncation the original single-suite (128-bit
     * CM, 30-octet key+salt) code used -- that shortcut only produces
     * the right answer when ckey_len happens to be a multiple of 3.
     * Key+salt sizes for AES-192/256 CM and AES-128/256 GCM are not
     * multiples of 3, so their base64 encoding legitimately requires
     * '=' padding in the final block.
     */
    expected_len = ((suite->ckey_len + 2) / 3) * 4;
    assert(expected_len <= MAX_KEY_LEN);
    skey = dlm + 1;
    if ((int)strlen(skey) != expected_len) {
        fprintf(stderr, "invalid length of base64 key encoding, expected %d, "
          "supplied %d\n", expected_len, (int)strlen(skey));
        return (NULL);
    }
    rval = malloc(sizeof(struct eaud_crypto));
    if (rval == NULL) {
        return (NULL);
    }
    memset(rval, '\0', sizeof(struct eaud_crypto));
    len = base64_string_to_octet_string(rval->key, &pad, skey, expected_len);
    /*
     * `len` is the number of *input* base64 characters consumed. If
     * decoding stopped short of the full string, that means padding
     * ('=') showed up somewhere before the final block, which is
     * malformed base64.
     */
    if (len != expected_len) {
        fprintf(stderr, "error: malformed base64 key/salt encoding "
              "(unexpected padding before end of string)\n");
        goto e0;
    }
    /*
     * `pad` (0, 1 or 2) is how many '=' characters were in the final
     * block, i.e. how many fewer than 3 octets that block decoded to.
     * Confirm the total decoded octet count matches what this suite
     * actually needs -- this is the real integrity check that replaces
     * the old blanket "no padding allowed" rule.
     */
    if ((len / 4) * 3 - pad != suite->ckey_len) {
        fprintf(stderr, "error: decoded key/salt length mismatch "
              "(expected %d octets, got %d)\n", suite->ckey_len,
              (len / 4) * 3 - pad);
        goto e0;
    }
    rval->suite = suite;
    suite->set_policy(&rval->policy.rtp);
    suite->set_policy(&rval->policy.rtcp);
    rval->policy.key = (uint8_t *)rval->key;
    rval->policy.next = NULL;
    rval->policy.window_size = 128;
    rval->policy.allow_repeat_tx = 0;
    return (rval);
e0:
    free(rval);
    return (NULL);
}

static int srtp_inited;

int
eaud_crypto_decrypt(struct eaud_crypto *crypto, uint8_t *pkt_raw, int pkt_len)
{
    int status;
#if defined(SRTP_PROTECT_LASTARG)
    SRTP_PROTECT_LASTARG octets_recvd;
#else
    size_t octets_recvd;
#endif
    rtp_hdr_t *rpkt;

    if (srtp_inited == 0) {
        status = srtp_init();
        if (status) {
            return (-1);
        }
        srtp_inited = 1;
    }
    if (crypto->srtp_ctx == NULL){
        rpkt = (rtp_hdr_t *)pkt_raw;
        crypto->policy.ssrc.value = ntohl(rpkt->ssrc);
        crypto->policy.ssrc.type  = ssrc_specific;
        status = srtp_create(&crypto->srtp_ctx, &crypto->policy);
        if (status != srtp_err_status_ok || crypto->srtp_ctx == NULL) {
            return (-1);
        }
    }
    octets_recvd = pkt_len;
    status = srtp_unprotect(crypto->srtp_ctx, pkt_raw, &octets_recvd);
    if (status){
       return (-1);
    }
    return (octets_recvd);
}
