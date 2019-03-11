/*
 * util.c
 *
 * Utilities used by the test apps
 *
 * John A. Foley
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2014, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <stdint.h>
#include "srtp_util.h"

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_block_to_octet_triple (char *out, char *in)
{
    unsigned char sextets[4] = {};
    int j = 0;
    int i;

    for (i = 0; i < 4; i++) {
        char *p = strchr(b64chars, in[i]);
        if (p != NULL) {
            sextets[i] = p - b64chars;
        } else{  j++; }
    }

    out[0] = (sextets[0] << 2) | (sextets[1] >> 4);
    if (j < 2) {
        out[1] = (sextets[1] << 4) | (sextets[2] >> 2);
    }
    if (j < 1) {
        out[2] = (sextets[2] << 6) | sextets[3];
    }
    return j;
}

int base64_string_to_octet_string (char *out, int *pad, char *in, int len)
{
    int k = 0;
    int i = 0;
    int j = 0;

    if (len % 4 != 0) {
        return 0;
    }

    while (i < len && j == 0) {
        j = base64_block_to_octet_triple(out + k, in + i);
        k += 3;
        i += 4;
    }
    *pad = j;
    return i;
}
