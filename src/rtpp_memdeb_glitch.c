/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_memdeb_internal.h"
#include "rtpp_memdeb_glitch.h"

struct _glav_trig _glav_trig = {.wild = 0, .stack = 0};

#define MDG_ENAME "MEMDEB_GLITCH_TRIG"
#define MDG_ACT_ENAME "MEMDEB_GLITCH_ACT"
#define MDG_CH_PORT "MEMDEB_GLITCH_CH_PORT"

enum {
  TRIG_STEP = 's',
  TRIG_WC = '*',
  TRIG_COOK = 'c'
};

struct mg_data {
    int _glav_orig;
    int mysocket;
};

static struct mg_data mgd;

void
rtpp_memdeb_callhome(intmax_t step, uintptr_t hash, struct memdeb_loc *mlp)
{
   char buffer[512]; /* +1 so we can \n */
   int len;
 
   len = snprintf(buffer, sizeof(buffer), "s%lld: c%lu\tcalled from %s() at %s:%d\n",
     (long long)mgd._glav_orig + step + 1, (unsigned long)hash, mlp->funcn, mlp->fname,
     mlp->linen);
   assert(send(mgd.mysocket, buffer, len, 0) == len);
}

void
rtpp_memdeb_glitch_init()
{
    const char *glav, *cp;

    glav = getenv(MDG_ENAME);
    if (glav != NULL) {
        int iglav = -1;
        unsigned long u;

        switch (glav[0]) {
        case TRIG_STEP:
            glav += 1;
            iglav = atoi(glav);
            assert(iglav >= -1);
            break;
        case TRIG_WC:
            assert(glav[1] == '\0');
            _glav_trig.wild = 1;
            break;
        case TRIG_COOK:
            u = 0;
            glav += 1;
            cp = strchr(glav, ':');
            if (cp != NULL && cp[1] == TRIG_WC) {
                _glav_trig.wild = 1;
            }
            assert(sscanf(glav, "%lu\n", &u) == 1);
            assert(u != 0);
            _glav_trig.stack = u;
            break;
        default:
            abort();
        }

        assert(unsetenv(MDG_ENAME) == 0);
        atomic_init(&_glav_trig.step, -(iglav + 1));
        atomic_init(&_glav_trig.hits, 0);
        mgd._glav_orig = iglav;

        int do_report = 0;
        const char *act = getenv(MDG_ACT_ENAME);
        if (act != NULL) {
            for (cp = &act[0]; *cp != '\0'; cp++) {
                switch (*cp) {
                case GLAV_ABORT:
                case GLAV_HANG:
                case GLAV_BAIL:
                case GLAV_GLTCH:
                    break;
                case GLAV_RPRT:
                    do_report = 1;
                    break;
                default:
                    abort();
                }
            }
            assert(cp - act <= sizeof(_glav_trig.act));
            strncpy(_glav_trig.act, act, sizeof(_glav_trig.act));
            assert(unsetenv(MDG_ACT_ENAME) == 0);
        } else {
            strncpy(_glav_trig.act, "g", sizeof(_glav_trig.act));
        }
        if (do_report != 0) {
            struct sockaddr_in dest;
            const char *sport = getenv(MDG_CH_PORT);
            assert(sport != NULL);
            int iport = atoi(sport);
            assert(iport > 0 && iport < 65536);
            assert(unsetenv(MDG_CH_PORT) == 0);
            mgd.mysocket = socket(AF_INET, SOCK_STREAM, 0);
            assert(mgd.mysocket >= 0);

            memset(&dest, 0, sizeof(dest));                /* zero the struct */
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* set destination IP number - localhost, 127.0.0.1*/
            assert(bind(mgd.mysocket, (struct sockaddr *)&dest,
              sizeof(struct sockaddr_in)) == 0);

            memset(&dest, 0, sizeof(dest));                /* zero the struct */
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* set destination IP number - localhost, 127.0.0.1*/
            dest.sin_port = htons(iport);                  /* set destination port number */

            assert(connect(mgd.mysocket, (struct sockaddr *)&dest,
              sizeof(struct sockaddr_in)) == 0);
        }
    } else {
        atomic_init(&_glav_trig.step, 0);
    }
}
