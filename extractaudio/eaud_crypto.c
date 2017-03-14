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

struct srtp_crypto_suite {
    const char *can_name;
    int key_size;
    int tag_size;
    int ckey_len;
    srtp_sec_serv_t sec_serv;
};

#define MAX_KEY_LEN      96

struct eaud_crypto {
    const struct srtp_crypto_suite *suite;
    srtp_policy_t policy;
    srtp_t srtp_ctx;
    char key[MAX_KEY_LEN];
};

static struct srtp_crypto_suite srtp_crypto_suites[] = {
    {.can_name = "AES_CM_128_HMAC_SHA1_32", .key_size = 128, .tag_size = 4,
     .ckey_len = 30, .sec_serv = sec_serv_conf_and_auth},
#if 0
    {.can_name = "F8_128_HMAC_SHA1_32", .key_size = 128, .tag_size = 4,
     .ckey_len = ???, .sec_serv = sec_serv_conf_and_auth},
#endif
  {.can_name = "AES_CM_128_HMAC_SHA1_32", .key_size = 128, .tag_size = 4,
   .ckey_len = 30, .sec_serv = sec_serv_conf_and_auth},
  {.can_name = "AES_CM_128_HMAC_SHA1_80", .key_size = 128, .tag_size = 10,
   .ckey_len = 30, .sec_serv = sec_serv_conf_and_auth},
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
    expected_len = (suite->ckey_len * 4) / 3;
    assert(expected_len <= MAX_KEY_LEN);
    skey = dlm + 1;
    if (strlen(skey) != expected_len) {
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
    if (pad != 0) {
        fprintf(stderr, "error: padding in base64 unexpected\n");
        goto e0;
    }
    if (len < expected_len) {
        fprintf(stderr, "error: too few digits in key/salt "
              "(should be %d digits, found %d)\n", expected_len, len);
        goto e0;;
    }
    rval->suite = suite;
    srtp_crypto_policy_set_rtp_default(&rval->policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&rval->policy.rtcp);
    rval->policy.key = (uint8_t *)rval->key;
    rval->policy.ekt = NULL; rval->policy.next = NULL;
    rval->policy.window_size = 128;
    rval->policy.allow_repeat_tx = 0;
    rval->policy.rtp.auth_tag_len = suite->tag_size;
    rval->policy.rtp.sec_serv = rval->policy.rtcp.sec_serv = suite->sec_serv;
    return (rval);
e0:
    free(rval);
    return (NULL);
}

static int srtp_inited;

int
eaud_crypto_decrypt(struct eaud_crypto *crypto, uint8_t *pkt_raw, int pkt_len)
{
    int status, octets_recvd;
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
