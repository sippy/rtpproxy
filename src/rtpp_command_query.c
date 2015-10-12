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
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_analyzer.h"
#include "rtpp_command.h"
#include "rtpp_command_private.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

#define CHECK_OVERFLOW() \
    if (len > sizeof(cmd->buf_t) - 2) { \
        CALL_METHOD(spa->log, write, RTPP_LOG_ERR, \
          "QUERY: output buffer overflow"); \
        return (ECODE_RTOOBIG_2); \
    }

static int
handle_query_simple(struct cfg *cf, struct rtpp_command *cmd,
  struct rtpp_session_obj *spa, int idx, int verbose)
{
    int len;

    if (verbose == 0) {
        len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d %lu %lu %lu %lu\n", get_ttl(spa),
          spa->stream[idx]->npkts_in, spa->stream[NOT(idx)]->npkts_in,
          spa->pcount.nrelayed, spa->pcount.ndropped);
    } else {
        len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "ttl=%d npkts_ina=%lu "
          "npkts_ino=%lu nrelayed=%lu ndropped=%lu\n", get_ttl(spa),
          spa->stream[idx]->npkts_in, spa->stream[NOT(idx)]->npkts_in,
          spa->pcount.nrelayed, spa->pcount.ndropped);
    }
    rtpc_doreply(cf, cmd->buf_t, len, cmd, 0);
    return (0);
}

#define PULL_RST() \
    if (rst_pulled == 0) { \
        rtpp_analyzer_stat(spa->stream[idx]->analyzer, &rst); \
        rst_pulled = 1; \
    }

int
handle_query(struct cfg *cf, struct rtpp_command *cmd,
  struct rtpp_session_obj *spa, int idx)
{
    int len, i, verbose, rst_pulled;
    char *cp;
    struct rtpp_analyzer_stats rst;

    verbose = 0;
    for (cp = cmd->argv[0] + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'v':
        case 'V':
            verbose = 1;
            break;

        default:
            CALL_METHOD(spa->log, write, RTPP_LOG_ERR,
              "QUERY: unknown command modifier `%c'", *cp);
            return (ECODE_PARSE_8);
        }
    }
    if (cmd->argc <= 4) {
        return (handle_query_simple(cf, cmd, spa, idx, verbose));
    }
    len = 0;
    rst_pulled = 0;
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
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%d",
              get_ttl(spa));
            continue;
        }
        if (strcmp(cmd->argv[i], "npkts_ina") == 0) {
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              spa->stream[idx]->npkts_in);
            continue;
        }
        if (strcmp(cmd->argv[i], "npkts_ino") == 0) {
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              spa->stream[NOT(idx)]->npkts_in);
            continue;
        }
        if (strcmp(cmd->argv[i], "nrelayed") == 0) {
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              spa->pcount.nrelayed);
            continue;
        }
        if (strcmp(cmd->argv[i], "ndropped") == 0) {
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%lu",
              spa->pcount.ndropped);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nsent") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%u",
              rst.psent);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nrcvd") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%u",
              rst.precvd);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_ndups") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%u",
              rst.pdups);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_nlost") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%d",
              rst.psent - rst.precvd);
            continue;
        }
        if (strcmp(cmd->argv[i], "rtpa_perrs") == 0) {
            PULL_RST();
            len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "%d",
              rst.pecount);
            continue;
        }
        CALL_METHOD(spa->log, write, RTPP_LOG_ERR,
              "QUERY: unsupported/invalid counter name `%s'", cmd->argv[i]);
        return (ECODE_QRYFAIL);
    }
    CHECK_OVERFLOW();
    len += snprintf(cmd->buf_t + len, sizeof(cmd->buf_t) - len, "\n");
    rtpc_doreply(cf, cmd->buf_t, len, cmd, 0);
    return (0);
}
