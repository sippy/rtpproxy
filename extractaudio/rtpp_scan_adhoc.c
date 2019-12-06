/*
 * Copyright (c) 2007-2019 Sippy Software, Inc., http://www.sippysoft.com
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "config.h"

#if HAVE_ERR_H
# include <err.h>
#endif

#include "rtpp_types.h"
#include "rtpp_loader.h"
#include "rtpp_record_private.h"
#include "eaud_adhoc.h"
#include "rtpp_scan_adhoc.h"

int
rtpp_scan_adhoc(struct rtpp_loader *loader, struct sessions *sessions)
{
    int pcount;
    unsigned char *cp, *ep;
    off_t st_size;
    struct adhoc_dissect pd;
    int rval;

    st_size = loader->sb.st_size;
    ep = loader->ibuf + st_size;

    pcount = 0;
    for (cp = loader->ibuf; cp < ep; cp = pd.nextcp) {
        rval = eaud_adhoc_dissect(cp, ep - cp, &pd);
        if (rval < 0) {
            if (rval == ADH_DSCT_EOF)
                continue;
            warnx("broken or truncated adhoc file");
            return -1;
        }
        pcount++;
    }
    if (cp != loader->ibuf + st_size) {
        warnx("invalid format, %d packets loaded", pcount);
        return -1;
    }
    return pcount;
}
