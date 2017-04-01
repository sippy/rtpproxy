/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_analyzer.h"
#include "rtpp_command.h"
#include "rtpp_command_private.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_util.h"
#include "rtpp_command_query.h"

#define CHECK_OVERFLOW() \
    if (len > sizeof(cmd->buf_t) - 2) { \
        RTPP_LOG(spp->log, RTPP_LOG_ERR, \
          "QUERY: output buffer overflow"); \
        return (ECODE_RTOOBIG_2); \
    }

static int
handle_query_simple(struct cfg *cf, struct rtpp_command *cmd,
  struct rtpp_pipe *spp, int idx, int verbose)
{
    int len, ttl;
    struct rtpps_pcount pcnts;
    struct rtpp_pcnts_strm pst[2];

    ttl = CALL_METHOD(spp, get_ttl);
    CALL_METHOD(spp->pcount, get_stats, &pcnts);
    CALL_METHOD(spp->stream[idx]->pcnt_strm, get_stats, &pst[0]);
    CALL_METHOD(spp->stream[NOT(idx)]->pcnt_strm, get_stats, &pst[1]);
    if (verbose == 0) {
        len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d %lu %lu %lu %lu\n",
          ttl, pst[0].npkts_in, pst[1].npkts_in, pcnts.nrelayed, pcnts.ndropped);
    } else {
        len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "ttl=%d npkts_ina=%lu "
          "npkts_ino=%lu nrelayed=%lu ndropped=%lu\n", ttl,
          pst[0].npkts_in, pst[1].npkts_in, pcnts.nrelayed, pcnts.ndropped);
    }
    rtpc_doreply(cmd, cmd->buf_t, len, 0);
    return (0);
}

#define PULL_RST() \
    if (rst_pulled == 0) { \
        CALL_METHOD(spp->stream[idx]->analyzer, get_stats, &rst); \
        rst_pulled = 1; \
    }

#define PULL_PCNT() \
    if (pcnt_pulled == 0) { \
        CALL_METHOD(spp->pcount, get_stats, &pcnts); \
        pcnt_pulled = 1; \
    }

#define PULL_PCNT_STRM() \
    if (pcnt_strm_pulled == 0) { \
        CALL_METHOD(spp->stream[idx]->pcnt_strm, get_stats, &pst[0]); \
        CALL_METHOD(spp->stream[NOT(idx)]->pcnt_strm, get_stats, &pst[1]); \
        pcnt_strm_pulled = 1; \
    }

int
handle_query(struct cfg *cf, struct rtpp_command *cmd,
  struct rtpp_pipe *spp, int idx)
{
    int len, i, verbose, rst_pulled, pcnt_pulled, pcnt_strm_pulled;
    char *cp;
    struct rtpa_stats rst;
    struct rtpps_pcount pcnts;
    struct rtpp_pcnts_strm pst[2];

    verbose = 0;
    for (cp = cmd->argv[0] + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'v':
        case 'V':
            verbose = 1;
            break;

        default:
            RTPP_LOG(spp->log, RTPP_LOG_ERR,
              "QUERY: unknown command modifier `%c'", *cp);
            return (ECODE_PARSE_8);
        }
    }
    if (cmd->argc <= 4) {
        return (handle_query_simple(cf, cmd, spp, idx, verbose));
    }
    len = 0;
    rst_pulled = pcnt_pulled = pcnt_strm_pulled = 0;
    for (i = 4; i < cmd->argc && len < (sizeof(cmd->buf_t) - 2); i++) {
        if (i > 4) {
            CHECK_OVERFLOW();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, " ");
        }
        if (verbose != 0) {
            CHECK_OVERFLOW();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%s=", \
              cmd->argv[i]);
        }
        CHECK_OVERFLOW();
        if (strcmp(cmd->argv[i], "ttl") == 0) {
            int ttl = CALL_METHOD(spp, get_ttl);
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%d",
              ttl);
            continue;
        }
        if (strcmp(cmd->argv[i], "npkts_ina") == 0) {
            PULL_PCNT_STRM();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              pst[0].npkts_in);
            continue;
        }
        if (strcmp(cmd->argv[i], "npkts_ino") == 0) {
            PULL_PCNT_STRM();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              pst[1].npkts_in);
            continue;
        }
        if (strcmp(cmd->argv[i], "nrelayed") == 0) {
            PULL_PCNT();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              pcnts.nrelayed);
            continue;
        }
        if (strcmp(cmd->argv[i], "ndropped") == 0) {
            PULL_PCNT();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              pcnts.ndropped);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nsent") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              rst.psent);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nrcvd") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              rst.precvd);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_ndups") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              rst.pdups);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nlost") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              rst.plost);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_perrs") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              rst.pecount);
            continue;
        }
        RTPP_LOG(spp->log, RTPP_LOG_ERR,
              "QUERY: unsupported/invalid counter name `%s'", cmd->argv[i]);
        return (ECODE_QRYFAIL);
    }
    CHECK_OVERFLOW();
    len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "\n");
    rtpc_doreply(cmd, cmd->buf_t, len, 0);
    return (0);
}
