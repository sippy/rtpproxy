/*
 * Copyright (c) 2026 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "config.h"

#if defined(HAVE_LIBCRYPTO)
#include <openssl/evp.h>
#endif

#include "rtpp_record_util.h"

#if defined(HAVE_LIBCRYPTO)
#define RCID_SHA256_AVAIL 1
#define RCID_METHODS      "raw, b64url, sha256"
#else
#define RCID_SHA256_AVAIL 0
#define RCID_METHODS      "raw, b64url"
#endif

static const struct {
    const char *name;
    int method;
    int avail;
} rcid_methods[] = {
    {"raw",    RTPP_RCID_RAW,    1},
    {"b64url", RTPP_RCID_B64URL, 1},
    {"sha256", RTPP_RCID_SHA256, RCID_SHA256_AVAIL},
};

#if defined(HAVE_LIBCRYPTO)
const char rtpp_record_callid_hash_usage[] = "raw|b64url|sha256";
#else
const char rtpp_record_callid_hash_usage[] = "raw|b64url";
#endif

/*
 * Parse the argument of the --record_callid_hash option into one of the
 * RTPP_RCID_* values. Returns 0 on success, or -1 with *emsgp pointing to
 * the reason if the method is unknown or not available in this build.
 */
int
rtpp_record_callid_hash_parse(const char *arg, int *methodp,
  const char **emsgp)
{
    size_t i;

    for (i = 0; i < sizeof(rcid_methods) / sizeof(rcid_methods[0]); i++) {
        if (strcmp(arg, rcid_methods[i].name) != 0)
            continue;
        if (!rcid_methods[i].avail) {
            *emsgp = "--record_callid_hash method is not available, "
              "rtpproxy has been built without OpenSSL";
            return (-1);
        }
        *methodp = rcid_methods[i].method;
        return (0);
    }
    *emsgp = "unknown --record_callid_hash method, supported: " RCID_METHODS;
    return (-1);
}

/*
 * Encode the Call-ID (src, slen, not NUL-terminated) into dst as selected
 * by method. Returns the length of the result, or -1 if it does not fit
 * into dlen bytes or cannot be built.
 */
static int
rcid_encode(char *dst, size_t dlen, const char *src, size_t slen, int method)
{
    static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i, j;
    uint32_t v;

    switch (method) {
    case RTPP_RCID_RAW:
        if (slen >= dlen)
            return (-1);
        memcpy(dst, src, slen);
        dst[slen] = '\0';
        return ((int)slen);

    case RTPP_RCID_B64URL:
        if (slen > (dlen - 1) / 4 * 3)
            return (-1);
        for (i = j = 0; i < slen; i += 3) {
            v = (uint32_t)(unsigned char)src[i] << 16;
            if (i + 1 < slen)
                v |= (uint32_t)(unsigned char)src[i + 1] << 8;
            if (i + 2 < slen)
                v |= (uint32_t)(unsigned char)src[i + 2];
            dst[j++] = b64url[(v >> 18) & 0x3f];
            dst[j++] = b64url[(v >> 12) & 0x3f];
            if (i + 1 < slen)
                dst[j++] = b64url[(v >> 6) & 0x3f];
            if (i + 2 < slen)
                dst[j++] = b64url[v & 0x3f];
        }
        dst[j] = '\0';
        return ((int)j);

#if defined(HAVE_LIBCRYPTO)
    case RTPP_RCID_SHA256: {
        static const char hex[] = "0123456789abcdef";
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen;

        if (EVP_Digest(src, slen, md, &mdlen, EVP_sha256(), NULL) != 1)
            return (-1);
        if ((size_t)mdlen * 2 >= dlen)
            return (-1);
        for (i = 0; i < mdlen; i++) {
            dst[i * 2] = hex[md[i] >> 4];
            dst[i * 2 + 1] = hex[md[i] & 0xf];
        }
        dst[i * 2] = '\0';
        return ((int)(i * 2));
    }
#endif

    default:
        return (-1);
    }
}

/*
 * Build the "<call-id>=<from-tag>" part of a recording file name into dst
 * (dlen bytes, NUL-terminated). The Call-ID and the from-tag are not
 * NUL-terminated. The from-tag is used as is, the Call-ID as selected by
 * method (RTPP_RCID_*): RTPP_RCID_RAW uses it as is, RTPP_RCID_B64URL
 * encodes it with the URL-safe base64 alphabet (RFC 4648 sec. 5) without
 * padding, so it can be recovered from the file name, and RTPP_RCID_SHA256
 * replaces it with its SHA-256 digest in lowercase hex. Neither of the
 * latter two can produce '/', and a raw Call-ID or a from-tag containing
 * '/' is refused, so the result never contains '/'.
 *
 * Returns the length of the result, or -1 with *emsgp pointing to the
 * reason.
 */
int
rtpp_record_callid_fname(char *dst, size_t dlen, const char *cid,
  size_t cidlen, const char *tag, size_t taglen, int method,
  const char **emsgp)
{
    int len;

    if (method == RTPP_RCID_RAW && memchr(cid, '/', cidlen) != NULL) {
        *emsgp = "call-id contains '/', refusing to use it in the recording "
          "file name (see --record_callid_hash)";
        return (-1);
    }
    if (memchr(tag, '/', taglen) != NULL) {
        *emsgp = "from-tag contains '/', refusing to use it in the recording "
          "file name";
        return (-1);
    }
    len = rcid_encode(dst, dlen, cid, cidlen, method);
    if (len < 0 || dlen - (size_t)len < taglen + 2) {
        *emsgp = "recording file name is too long";
        return (-1);
    }
    dst[len++] = '=';
    memcpy(dst + len, tag, taglen);
    len += (int)taglen;
    dst[len] = '\0';
    return (len);
}
