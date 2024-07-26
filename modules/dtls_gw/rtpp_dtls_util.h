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

#pragma once

#define FP_DIGEST_ALG "SHA-256"
#define FP_DIGEST_ALG_LEN (sizeof(FP_DIGEST_ALG) - 1)
#define FP_DIGEST_LEN 32
#define FP_FINGERPRINT_STR_LEN ((FP_DIGEST_LEN * 2) + (FP_DIGEST_LEN - 1))
#define FP_DIGEST_STR_LEN ((sizeof(FP_DIGEST_ALG) - 1) + 1 + \
  FP_FINGERPRINT_STR_LEN)
#define FP_DIGEST_STRBUF_LEN (FP_DIGEST_STR_LEN + 1)

typedef struct x509_st X509;

int rtpp_dtls_fp_gen(const X509 *, char *, int);
