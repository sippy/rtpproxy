/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2021 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <assert.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#if HAVE_ERR_H
# include <err.h>
#endif

#include "rtpp_types.h"
#include "format_au.h"
#include "g711.h"
#include "rtp_info.h"
#include "decoder.h"
#include "eaud_session.h"
#include "rtpp_record_adhoc.h"
#include "rtpp_record_private.h"
#include "rtpp_ssrc.h"
#include "rtp_analyze.h"
#include "rtpp_loader.h"
#include "rtp.h"
#include "rtpa_stats.h"
#include "eaud_oformats.h"
#include "eaud_substreams.h"

#ifdef RTPP_CHECK_LEAKS
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_APP_STATIC;
#endif

const static char *usage_msg[2] = {
  "%s\n",
  "usage: extractframes infile [outprefix]"
};

static void
usage(void)
{

    fprintf(stderr, usage_msg[0], usage_msg[1]);
    exit(1);
}

int
main(int argc, char **argv)
{
    int oblen, delete, stereo, idprio, nch;
    uint64_t nasamples, nbsamples, nwsamples;
    struct channels channels, act_subset, *ap;
    struct cnode *cnp;
    double basetime;
    int64_t isample, sync_sample;

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_APP_INIT();
#endif

    MYQ_INIT(&channels);
    MYQ_INIT(&act_subset);

    delete = stereo = idprio = 0;
    isample = -1;
    sync_sample = 0;

    if (argc < 2 || argc > 3) {
        usage();
    }

    if (eaud_session_load(argv[1], &channels, A_CH, NULL) < 0) {
        errx(1, "cannot load %s", argv[1]);
    }

    if (MYQ_EMPTY(&channels))
        goto theend;

    MYQ_FOREACH(cnp, &channels) {
        cnp->cp->btime = MYQ_FIRST(&(cnp->cp->session))->pkt->time;
        cnp->cp->etime = MYQ_LAST(&(cnp->cp->session))->pkt->time;
    }

    nch = 0;
    basetime = MYQ_FIRST(&channels)->cp->btime;
#if 0
    fprintf(stderr, "%f %f\n", MYQ_FIRST(&(MYQ_FIRST(&channels)->session))->pkt->time, MYQ_FIRST(&channels)->btime);
#endif
    MYQ_FOREACH(cnp, &channels) {
        if (basetime > cnp->cp->btime)
            basetime = cnp->cp->btime;
    }
    MYQ_FOREACH(cnp, &channels) {
        cnp->cp->skip = (cnp->cp->btime - basetime) * 8000;
        nch++;
    }

    oblen = 0;

    ap = &channels;
    nasamples = nbsamples = nwsamples = 0;
    do {
        MYQ_FOREACH(cnp, ap) {
        }
    } while (0);

theend:
    return 0;
}
