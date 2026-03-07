/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2026 Sippy Software, Inc., http://www.sippysoft.com
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

#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <assert.h>

#include "config_pp.h"
#include "rtpp_str.h"
#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_bindaddr.h"
#include "rtpp_bindargs.h"
#include "rtpp_bindaddrs.h"
#include "rtpp_cfg.h"

void
bindarg_parse(struct bindarg *bap, char *barg, int is_v6)
{
    char *cp = strchr(barg, '@');
    if (cp != NULL) {
        cp[0] = '\0';
        bap->params.label = rtpp_str_const_i(barg);
        barg = cp + 1;
    }
    cp = strchr(barg, '=');
    if (cp != NULL) {
        cp[0] = '\0';
        cp += 1;
        bap->params.advaddr = rtpp_str_const_i(cp);
    }
    bap->h = barg;
    bap->is_v6 = is_v6;
}

static int
ba_firstidx(const struct bindarg bargs[], int banum, int v6)
{
    for (int i = 0; i < banum; i++) {
        if (bargs[i].is_v6 == v6)
            return i;
    }
    return -1;
}

int
init_bindaddrs(struct rtpp_cfg *cfsp, struct bindarg bargs[], int banum,
  const struct rtpp_bindaddr_params iebparams[2])
{
    int i;
    char *bh1;
    const char *errmsg;

    if (banum == 0) {
        bargs[0].h = "*";
        banum = 1;
    } else {
        struct bindarg iaddr = {0}, eaddr = {0};
        int f_idx[2] = {ba_firstidx(bargs, banum, 0),
                        ba_firstidx(bargs, banum, 1)};
        for (int j = 0; j < 2; j++) {
            i = f_idx[j];
            if (i < 0)
                continue;
            bh1 = strchr(bargs[i].h, '/');
            if (bh1 != NULL) {
                if (eaddr.h != NULL) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "either IPv4 or IPv6 should be configured for external "
                      "interface in bridging mode, not both");
                    return (-1);
                }
                cfsp->bmode = 1;
                bh1[0] = '\0';
                eaddr = bargs[i];
                eaddr.h = bh1 + 1;
                if (bargs[i].h == bh1) {
                    bargs[i].h = NULL;
                }
            }
        }
        if (cfsp->bmode) {
            for (int j = 0; j < 2; j++) {
                i = f_idx[j];
                if (i < 0)
                    continue;
                if (bargs[i].h == NULL)
                    continue;
                if (iaddr.h != NULL) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "either IPv4 or IPv6 should be configured for internal "
                      "interface in bridging mode, not both");
                    return (-1);
                }
                iaddr = bargs[i];
                bargs[i].h = NULL;
            }
            if (iaddr.h == NULL || eaddr.h == NULL) {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "incomplete configuration of the bridging mode - exactly "
                  "2 listen addresses required");
                return (-1);
            }
            if (iebparams[0].advaddr.s != NULL && iebparams[1].advaddr.s == NULL) {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "two advertised addresses are required for internal "
                  "and external interfaces in bridging mode");
                return (-1);
            }
            for (i = 0; i < 2; i++) {
                const struct bindarg *bap = (i == 0) ? &iaddr : &eaddr;
                if (bap->params.label.s != NULL) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "bridging address(es) cannot have a label");
                    return (-1);
                }
                if (bap->params.advaddr.s != NULL) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "bridging address(es) cannot have an advertized"
                      "address, use matching -A argument");
                    return (-1);
                }
                int rmode = AI_ADDRCONFIG | AI_PASSIVE;
                rmode |= cfsp->no_resolve ? AI_NUMERICHOST : 0;
                cfsp->bindaddr[i] = CALL_SMETHOD(cfsp->bindaddrs_cf,
                  host2, bap->h, bap->is_v6 ? AF_INET6 : AF_INET, rmode, &errmsg,
                  &iebparams[i]);
                if (cfsp->bindaddr[i] == NULL) {
                    RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "host2bindaddr(%s): %s", bap->h, errmsg);
                    return (-1);
                }
            }
        }
    }

    for (i = 0; i < banum; i++) {
        const struct rtpp_bindaddr *baddr;
        if (bargs[i].h == NULL)
            continue;
        if (cfsp->bindaddr[0] != NULL && bargs[i].params.label.s == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "address label is missing");
            return (-1);
        }
        if (strchr(bargs[i].h, '/') != NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "only the first %s listening address can have external part",
              bargs[i].is_v6 ? "IPv6" : "IPv4");
            return (-1);
        }
        int rmode = AI_ADDRCONFIG | AI_PASSIVE;
        rmode |= cfsp->no_resolve ? AI_NUMERICHOST : 0;
        baddr = CALL_SMETHOD(cfsp->bindaddrs_cf,
          host2, bargs[i].h, bargs[i].is_v6 ? AF_INET6 : AF_INET, rmode,
          &errmsg, &bargs[i].params);
        if (baddr == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "host2bindaddr(%s): %s", bargs[i].h, errmsg);
            return (-1);
        }
        if (cfsp->bindaddr[0] == NULL)
            cfsp->bindaddr[0] = baddr;
    }

    assert(cfsp->bindaddr[0] != NULL && cfsp->bindaddr[0]->addr != NULL);
    return (0);
}
