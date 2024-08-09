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

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "rtpp_dtls_util.h"

int
rtpp_dtls_fp_gen(const X509 *cert, char *buf, int len)
{
    uint8_t fp[FP_DIGEST_LEN] = {0};
    unsigned int fp_len, i;

    if (len < FP_DIGEST_STRBUF_LEN)
        return (-1);
    fp_len = sizeof(fp);
    if (X509_digest(cert, EVP_sha256(), fp, &fp_len) != 1) {
        ERR_clear_error();
        return (-1);
    }
    memcpy(buf, FP_DIGEST_ALG, sizeof(FP_DIGEST_ALG) - 1);
    buf += sizeof(FP_DIGEST_ALG) - 1;
    buf[0] = ' ';
    buf++;
    for (i = 0; i < FP_DIGEST_LEN; i++) {
        sprintf(buf, "%.2X", fp[i]);
        buf += 2;
        if (i != (FP_DIGEST_LEN - 1)) {
            buf[0] = ':';
            buf++;
        }
    }
    return (0);
}
