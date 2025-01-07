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
#include <assert.h>
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
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_pcount.h"
#include "rtpp_time.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_pcnts_strm.h"
#include "rtpp_pipe.h"
#include "rtpp_codeptr.h"
#include "rtpp_stream.h"
#include "rtpp_util.h"
#include "commands/rpcpv1_query.h"
#include "rtpp_command_reply.h"

#define CHECK_OVERFLOW() \
    if (aerr != 0) { \
        RTPP_LOG(spp->log, RTPP_LOG_ERR, \
          "QUERY: output buffer overflow"); \
        return (ECODE_RTOOBIG_2); \
    }

static int
handle_query_simple(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  struct rtpp_pipe *spp, int idx, int verbose)
{
    int aerr, ttl;
    struct rtpps_pcount pcnts;
    struct rtpp_pcnts_strm pst[2];

    ttl = CALL_SMETHOD(spp, get_ttl);
    CALL_SMETHOD(spp->pcount, get_stats, &pcnts);
    CALL_SMETHOD(spp->stream[idx]->pcnt_strm, get_stats, &pst[0]);
    CALL_SMETHOD(spp->stream[NOT(idx)]->pcnt_strm, get_stats, &pst[1]);
    if (verbose == 0) {
        aerr = CALL_SMETHOD(cmd->reply, appendf, "%d %lu %lu %lu %lu",
          ttl, pst[0].npkts_in, pst[1].npkts_in, pcnts.nrelayed, pcnts.ndropped);
    } else {
        aerr = CALL_SMETHOD(cmd->reply, appendf, "ttl=%d npkts_ina=%lu "
          "npkts_ino=%lu nrelayed=%lu ndropped=%lu", ttl,
          pst[0].npkts_in, pst[1].npkts_in, pcnts.nrelayed, pcnts.ndropped);
    }
    return (aerr);
}

#define PULL_RST() \
    if (rst_pulled == 0) { \
        CALL_SMETHOD(spp->stream[idx]->analyzer, get_stats, &rst); \
        rst_pulled = 1; \
    }

#define PULL_JRST() \
    if (jrst_pulled == 0) { \
        if (CALL_SMETHOD(spp->stream[idx]->analyzer, get_jstats, &jrst) == 0) \
            jrst = (typeof(jrst)){0}; \
        jrst_pulled = 1; \
    }

#define PULL_PCNT() \
    if (pcnt_pulled == 0) { \
        CALL_SMETHOD(spp->pcount, get_stats, &pcnts); \
        pcnt_pulled = 1; \
    }

#define PULL_PCNT_STRM() \
    if (pcnt_strm_pulled == 0) { \
        CALL_SMETHOD(spp->stream[idx]->pcnt_strm, get_stats, &pst[0]); \
        CALL_SMETHOD(spp->stream[NOT(idx)]->pcnt_strm, get_stats, &pst[1]); \
        pcnt_strm_pulled = 1; \
    }

#define SUBC_FAIL_RSP " && -1"
#define SUBC_OK_RSP   " && 0"

int
handle_query(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  struct rtpp_pipe *spp, int idx)
{
    int aerr = 0, i, verbose, rst_pulled, pcnt_pulled, pcnt_strm_pulled;
    int jrst_pulled;
    const char *cp;
    struct rtpa_stats rst;
    struct rtpa_stats_jitter jrst;
    struct rtpps_pcount pcnts;
    struct rtpp_pcnts_strm pst[2];

    verbose = 0;
    for (cp = cmd->args.v[0].s + 1; *cp != '\0'; cp++) {
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
    if (cmd->args.c <= 4) {
        aerr = handle_query_simple(cfsp, cmd, spp, idx, verbose);
        goto out;
    }
    rst_pulled = pcnt_pulled = pcnt_strm_pulled = jrst_pulled = 0;
    for (i = 4; i < cmd->args.c && aerr == 0; i++) {
        if (i > 4) {
            CHECK_OVERFLOW();
            aerr = CALL_SMETHOD(cmd->reply, appendf, " ");
        }
        if (verbose != 0) {
            CHECK_OVERFLOW();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%.*s=", \
              FMTSTR(&cmd->args.v[i]));
        }
        CHECK_OVERFLOW();
        if (strcmp(cmd->args.v[i].s, "ttl") == 0) {
            int ttl = CALL_SMETHOD(spp, get_ttl);
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%d",
              ttl);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "npkts_ina") == 0) {
            PULL_PCNT_STRM();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              pst[0].npkts_in);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "npkts_ino") == 0) {
            PULL_PCNT_STRM();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              pst[1].npkts_in);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "longest_ipi") == 0) {
            PULL_PCNT_STRM();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%f",
              pst[0].longest_ipi);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_jlast") == 0) {
            PULL_JRST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%f",
              jrst.jlast);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_jmax") == 0) {
            PULL_JRST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%f",
              jrst.jmax);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_javg") == 0) {
            PULL_JRST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%f",
              jrst.javg);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "nrelayed") == 0) {
            PULL_PCNT();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              pcnts.nrelayed);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "ndropped") == 0) {
            PULL_PCNT();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              pcnts.ndropped);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_nsent") == 0) {
            PULL_RST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              rst.psent);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_nrcvd") == 0) {
            PULL_RST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              rst.precvd);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_ndups") == 0) {
            PULL_RST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              rst.pdups);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_nlost") == 0) {
            PULL_RST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              rst.plost);
            continue;
        }
        if (strcmp(cmd->args.v[i].s, "rtpa_perrs") == 0) {
            PULL_RST();
            aerr = CALL_SMETHOD(cmd->reply, appendf, "%lu",
              rst.pecount);
            continue;
        }
        RTPP_LOG(spp->log, RTPP_LOG_ERR,
          "QUERY: unsupported/invalid counter name `%.*s'",
          FMTSTR(&cmd->args.v[i]));
        return (ECODE_QRYFAIL);
    }
    CHECK_OVERFLOW();
out:
    if (cmd->subc.n > 0) {
        assert(CALL_SMETHOD(cmd->reply, reserve, sizeof(SUBC_FAIL_RSP)) == 0);
    }
    aerr = 0;
    for (int i = 0, skipped = 0; i < cmd->subc.n; i++) {
        CALL_SMETHOD(cmd->reply, commit);
        struct rtpp_subc_ctx rsc = {
            .sessp = cmd->sp,
            .strmp_in = spp->stream[idx],
            .strmp_out = spp->stream[NOT(idx)],
            .subc_args = &(cmd->subc.args[i]),
            .resp = &(cmd->subc.res[i])
        };
        rsc.resp->result = cmd->after_success[i].handler(
          &cmd->after_success[i].args, &rsc);
        if (rsc.resp->result != 0) {
            while (skipped >= 0) {
                 aerr = CALL_SMETHOD(cmd->reply, appendf,
                   " && %d", cmd->subc.res[i - skipped].result);
                 if (aerr)
                    break;
                 skipped -= 1;
            }
            break;
        }
        if (cmd->subc.res[i].buf_t[0] != '\0') {
            while (skipped > 0) {
                 aerr = CALL_SMETHOD(cmd->reply, appendf, SUBC_OK_RSP);
                 if (aerr)
                    break;
                 skipped -= 1;
            }
            aerr = CALL_SMETHOD(cmd->reply, appendf,
                " && %s", cmd->subc.res[i].buf_t);
            if (aerr)
                break;
        } else {
            skipped += 1;
        }
    }
    if (aerr)
        assert(CALL_SMETHOD(cmd->reply, append, SUBC_FAIL_RSP, strlen(SUBC_FAIL_RSP), 1) == 0);
    assert(CALL_SMETHOD(cmd->reply, append, "\n", 2, 1) == 0);
    CALL_SMETHOD(cmd->reply, commit);
    CALL_SMETHOD(cmd->reply, deliver, 0);
    return (0);
}
