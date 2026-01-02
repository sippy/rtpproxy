/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <ctype.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg.h"
#include "rtpp_defines.h"
#include "rtpp_bindaddrs.h"
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_async.h"
#include "commands/rpcpv1_copy.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_hash_table.h"
#include "rtpp_pipe.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_sessinfo.h"
#include "rtpp_socket.h"
#include "rtp_resizer.h"
#include "rtpp_mallocs.h"
#include "rtpp_network.h"
#include "rtpp_tnotify_set.h"
#include "rtpp_timeout_data.h"
#include "rtpp_util.h"
#include "rtpp_ttl.h"
#include "rtpp_nofile.h"
#include "rtpp_proc_async.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc.h"
#include "commands/rpcpv1_record.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_stats.h"

#define FREE_IF_NULL(p)	{if ((p) != NULL) {free(p); (p) = NULL;}}

struct ul_reply {
    const struct sockaddr *ia;
    const char *ia_ov;
    int port;
};

struct ul_opts {
    int asymmetric;
    int weak;
    int requested_ptime;
    char *codecs;
    const rtpp_str_t *addr;
    const rtpp_str_t *port;
    struct sockaddr *ia[2];
    const struct sockaddr *lia[2];

    struct ul_reply reply;
    
    int lidx;
    const struct sockaddr *local_addr;
    const rtpp_str_t *notify_socket;
    rtpp_str_const_t notify_tag;
    int pf;
    int new_port;

    int onhold;
};

#define BC_appendf(f, ...) { \
    if (CALL_SMETHOD(cmd->reply, appendf, f, ##__VA_ARGS__) != 0) \
        goto subc_nomem; \
}

#define BC_append(b) { \
    int _s = (sizeof(b) - 1); \
    if (CALL_SMETHOD(cmd->reply, append, b, _s, 0) != 0) \
        goto subc_nomem; \
}

void
ul_reply_port(struct rtpp_command *cmd, struct ul_reply *ulr)
{
    int rport, r;
    const char subc_err[] = " && -1";
    const char subc_ok[] = " && 0";

    r = CALL_SMETHOD(cmd->reply, reserve, 2);
    assert(r == 0);
    if (ulr == NULL || ulr->ia == NULL || ishostnull(ulr->ia)) {
        rport = (ulr == NULL) ? 0 : ulr->port;
        r = CALL_SMETHOD(cmd->reply, appendf, "%d", rport);
    } else {
        if (ulr->ia_ov == NULL) {
            r = CALL_SMETHOD(cmd->reply, append_port_addr, ulr->ia, ulr->port);
        } else {
            r = CALL_SMETHOD(cmd->reply, append_port_addr_s, ulr->ia_ov, ulr->port,
              ulr->ia->sa_family);
        }
    }
    assert(r == 0);
    if (cmd->subc.n > 0) {
        r = CALL_SMETHOD(cmd->reply, reserve, sizeof(subc_err) - 1 + 2);
        assert(r == 0);
    }
    int skipped = 0;
    for (int i = 0; i < cmd->subc.n; i++) {
        if (cmd->subc.res[i].result != 0) {
            while (skipped > 0) {
                BC_append(subc_ok);
                skipped -= 1;
            }
            BC_appendf(" && %d", cmd->subc.res[i].result);
        } else if (cmd->subc.res[i].buf_t[0] != '\0') {
            while (skipped > 0) {
                BC_append(subc_ok);
                skipped -= 1;
            }
            BC_appendf(" && %s", cmd->subc.res[i].buf_t);
        } else {
            skipped += 1;
        }
    }
    if (0) {
subc_nomem:
        r = CALL_SMETHOD(cmd->reply, append, subc_err, sizeof(subc_err) - 1, 1);
        assert(r == 0);
    }
    r = CALL_SMETHOD(cmd->reply, append, "\n", 2, 1);
    assert(r == 0);
    CALL_SMETHOD(cmd->reply, commit);
    CALL_SMETHOD(cmd->reply, deliver, (ulr != NULL) ? 0 : 1);
}

static void
ul_opts_init(const struct rtpp_cfg *cfsp, struct ul_opts *ulop)
{

    ulop->asymmetric = (cfsp->aforce != 0) ? 1 : 0;
    ulop->requested_ptime = -1;
    ulop->lia[0] = ulop->lia[1] = ulop->reply.ia = cfsp->bindaddr[0];
    ulop->lidx = 1;
    ulop->pf = AF_INET;
}

void
rtpp_command_ul_opts_free(struct ul_opts *ulop)
{

    FREE_IF_NULL(ulop->codecs);
    FREE_IF_NULL(ulop->ia[0]);
    FREE_IF_NULL(ulop->ia[1]);
    free(ulop);
}

#define	IPSTR_MIN_LENv4	7	/* "1.1.1.1" */
#define	IPSTR_MAX_LENv4	15	/* "255.255.255.255" */
#define	IPSTR_MIN_LENv6	2	/* "::" */
#define	IPSTR_MAX_LENv6	45

#define	IS_IPSTR_VALID(ips, pf)	((pf) == AF_INET ? \
  (strlen(ips) >= IPSTR_MIN_LENv4 && strlen(ips) <= IPSTR_MAX_LENv4) : \
  (strlen(ips) >= IPSTR_MIN_LENv6 && strlen(ips) <= IPSTR_MAX_LENv6))

struct ul_opts *
rtpp_command_ul_opts_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    int len, tpf, n, i, ai_flags;
    char *hostname;
    const char *cp, *t;
    rtpp_str_const_t notify_tag;
    const char *errmsg;
    struct sockaddr_storage tia;
    struct ul_opts *ulop;

    ulop = rtpp_zmalloc(sizeof(struct ul_opts));
    if (ulop == NULL) {
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    ul_opts_init(cfsp, ulop);
    if (cmd->cca.op == UPDATE && cmd->args.c > 6) {
        if (cmd->args.c == 8) {
            ulop->notify_socket = rtpp_str_fix(&cmd->args.v[6]);
            notify_tag = cmd->args.v[7];
        } else {
            ulop->notify_socket = rtpp_str_fix(&cmd->args.v[5]);
            notify_tag = cmd->args.v[6];
            cmd->cca.to_tag = NULL;
        }
        len = url_unquote((uint8_t *)notify_tag.s, notify_tag.len);
        if (len == -1) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
              "command syntax error - invalid URL encoding");
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_10);
            goto err_undo_1;
        }
        notify_tag.len = len;
        ulop->notify_tag = notify_tag;
    }
    ulop->addr = rtpp_str_fix(&cmd->args.v[2]);
    ulop->port = rtpp_str_fix(&cmd->args.v[3]);
    /* Process additional command modifiers */
    for (cp = cmd->args.v[0].s + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'a':
        case 'A':
            ulop->asymmetric = 1;
            break;

        case 'e':
        case 'E':
            if (ulop->lidx < 0 || cfsp->bindaddr[1] == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_11);
                goto err_undo_1;
            }
            ulop->lia[ulop->lidx] = cfsp->bindaddr[1];
            ulop->lidx--;
            break;

        case 'i':
        case 'I':
            if (ulop->lidx < 0 || cfsp->bindaddr[1] == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_12);
                goto err_undo_1;
            }
            ulop->lia[ulop->lidx] = cfsp->bindaddr[0];
            ulop->lidx--;
            break;

        case '6':
            ulop->pf = AF_INET6;
            break;

        case 's':
        case 'S':
            ulop->asymmetric = 0;
            break;

        case 'w':
        case 'W':
            ulop->weak = 1;
            break;

        case 'z':
        case 'Z':
            ulop->requested_ptime = strtol(cp + 1, (char **)&cp, 10);
            if (ulop->requested_ptime <= 0 || ulop->requested_ptime >= 1000) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_13);
                goto err_undo_1;
            }
            cp--;
            break;

        case 'c':
        case 'C':
            cp += 1;
            for (t = cp; *cp != '\0'; cp++) {
                if (!isdigit(*cp) && *cp != ',')
                    break;
            }
            if (t == cp || ulop->codecs != NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_14);
                goto err_undo_1;
            }
            ulop->codecs = malloc(cp - t + 1);
            if (ulop->codecs == NULL) {
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_2);
                goto err_undo_1;
            }
            memcpy(ulop->codecs, t, cp - t);
            ulop->codecs[cp - t] = '\0';
            cp--;
            break;

        case 'l':
        case 'L':
            len = extractaddr(cp + 1, &t, &cp, &tpf);
            if (len == -1) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_15);
                goto err_undo_1;
            }
            if (tpf != ulop->pf) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "mismatched protocol (%d local, %d session)",
                  tpf, ulop->pf);
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_1);
                goto err_undo_1;
            }
            hostname = alloca(len + 1);
            memcpy(hostname, t, len);
            hostname[len] = '\0';
            ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
            ai_flags |= cfsp->no_resolve ? AI_NUMERICHOST : 0;
            ulop->local_addr = CALL_METHOD(cfsp->bindaddrs_cf, host2, hostname,
              tpf, ai_flags, &errmsg);
            if (ulop->local_addr == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "invalid local address: %s: %s", hostname, errmsg);
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_1);
                goto err_undo_1;
            }
            cp--;
            break;

        case 'r':
        case 'R':
            len = extractaddr(cp + 1, &t, &cp, &tpf);
            if (len == -1) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_16);
                goto err_undo_1;
            }
            hostname = alloca(len + 1);
            memcpy(hostname, t, len);
            hostname[len] = '\0';
            ulop->local_addr = CALL_METHOD(cfsp->bindaddrs_cf, local4remote, cfsp,
              cmd->glog, tpf, hostname, SERVICE);
            if (ulop->local_addr == NULL) {
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_2);
                goto err_undo_1;
            }
            cp--;
            break;

        case 'n':
        case 'N':
            ulop->new_port = 1;
            break;

        default:
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "unknown command modifier `%c'",
              *cp);
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_5);
            goto err_undo_1;
        }
    }
    if (ulop->local_addr == NULL && ulop->lidx == 1 &&
      ulop->pf != ulop->lia[0]->sa_family) {
        /*
         * When there is no explicit direction specified via "E"/"I" and no
         * local/remote address provided either via "R" or "L" make sure we
         * pick up address that matches the address family of the stream.
         */
        ulop->local_addr = CALL_METHOD(cfsp->bindaddrs_cf, foraf,
          ulop->pf);
        if (ulop->local_addr == NULL) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "cannot match local "
              "address for the %s session", AF2STR(ulop->pf));
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_6);
            goto err_undo_1;
        }
    }
    if (ulop->addr != NULL && ulop->port != NULL && IS_IPSTR_VALID(ulop->addr->s, ulop->pf)) {
        n = resolve(sstosa(&tia), ulop->pf, ulop->addr->s, ulop->port->s, AI_NUMERICHOST);
        if (n == 0) {
            if (!ishostnull(sstosa(&tia))) {
                for (i = 0; i < 2; i++) {
                    ulop->ia[i] = malloc(SS_LEN(&tia));
                    if (ulop->ia[i] == NULL) {
                        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_3);
                        goto err_undo_1;
                    }
                    memcpy(ulop->ia[i], &tia, SS_LEN(&tia));
                }
                /* Set port for RTCP, will work both for IPv4 and IPv6 */
                n = ntohs(satosin(ulop->ia[1])->sin_port);
                satosin(ulop->ia[1])->sin_port = htons(n + 1);
            } else {
                ulop->onhold = 1;
            }
        } else {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "getaddrinfo(pf=%d, addr=%s, port=%s): %s",
              ulop->pf, ulop->addr->s, ulop->port->s, gai_strerror(n));
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_INVLARG_7);
            goto err_undo_1;
        }
    }
    return (ulop);

err_undo_1:
    rtpp_command_ul_opts_free(ulop);
err_undo_0:
    return (NULL);
}

static void
handle_nomem(struct rtpp_command *cmd, int ecode, struct rtpp_session *spa)
{

    RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "can't allocate memory");
    if (spa != NULL) {
        RTPP_OBJ_DECREF(spa);
    }
    CALL_SMETHOD(cmd->reply, deliver_error, ecode);
}

int
rtpp_command_ul_handle(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd, int sidx)
{
    int pidx, lport, sessions_active;
    struct rtpp_socket *fds[2];
    const char *actor;
    struct rtpp_session *spa, *spb;
    struct rtpp_socket *fd;
    struct ul_opts *ulop;

    pidx = 1;
    lport = 0;
    spa = spb = NULL;
    fds[0] = fds[1] = NULL;
    ulop = cmd->cca.opts.ul;

    if (cmd->cca.op == UPDATE) {
        if (!CALL_METHOD(cfsp->rtpp_tnset_cf, isenabled) && ulop->notify_socket != NULL) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "must permit notification socket with -n");
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NSOFF);
            goto err_undo_0;
        }
    }

    if (sidx != -1) {
        RTPP_DBG_ASSERT(cmd->cca.op == UPDATE || cmd->cca.op == LOOKUP);
        spa = cmd->sp;
        fd = CALL_SMETHOD(spa->rtp->stream[sidx], get_skt, HEREVAL);
        if (fd == NULL || ulop->new_port != 0) {
            if (ulop->local_addr != NULL) {
                spa->rtp->stream[sidx]->laddr = ulop->local_addr;
            } else if (ulop->new_port != 0 && ulop->lidx == -1 && spa->rtp->stream[sidx]->laddr != ulop->lia[0]) {
                spa->rtp->stream[sidx]->laddr = ulop->lia[0];
            }
            if (rtpp_create_listener(cfsp, spa->rtp->stream[sidx]->laddr, &lport, fds) == -1) {
                if (fd != NULL)
                    RTPP_OBJ_DECREF(fd);
                RTPP_LOG(spa->log, RTPP_LOG_ERR, "can't create listener");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_LSTFAIL_1);
                goto err_undo_0;
            }
            if (fd != NULL && ulop->new_port != 0) {
                RTPP_LOG(spa->log, RTPP_LOG_INFO,
                  "new port requested, releasing %d/%d, replacing with %d/%d",
                  spa->rtp->stream[sidx]->port, spa->rtcp->stream[sidx]->port, lport, lport + 1);
                CALL_SMETHOD(cfsp->sessinfo, update, spa, sidx, fds);
            } else {
                CALL_SMETHOD(cfsp->sessinfo, append, spa, sidx, fds);
            }
            CALL_METHOD(cfsp->rtpp_proc_cf, nudge);
            RTPP_OBJ_DECREF(fds[0]);
            RTPP_OBJ_DECREF(fds[1]);
            spa->rtp->stream[sidx]->port = lport;
            spa->rtcp->stream[sidx]->port = lport + 1;
            if (spa->complete == 0) {
                rtpp_command_get_stats(cmd)->nsess_complete.cnt++;
                CALL_SMETHOD(spa->rtp->stream[0]->ttl, reset_with,
                  cfsp->max_ttl);
                CALL_SMETHOD(spa->rtp->stream[1]->ttl, reset_with,
                  cfsp->max_ttl);
            }
            spa->complete = 1;
        }
        if (fd != NULL) {
            RTPP_OBJ_DECREF(fd);
        }
        if (ulop->weak)
            spa->rtp->stream[sidx]->weak = 1;
        else if (cmd->cca.op == UPDATE)
            spa->strong = 1;
        lport = spa->rtp->stream[sidx]->port;
        ulop->lia[0] = spa->rtp->stream[sidx]->laddr;
        pidx = (sidx == 0) ? 1 : 0;
        if (cmd->cca.op == UPDATE) {
            RTPP_LOG(spa->log, RTPP_LOG_INFO,
              "adding %s flag to existing session, new=%d/%d/%d",
              ulop->weak ? ( sidx ? "weak[1]" : "weak[0]" ) : "strong",
              spa->strong, spa->rtp->stream[0]->weak, spa->rtp->stream[1]->weak);
        }
        CALL_SMETHOD(spa->rtp->stream[0]->ttl, reset);
        CALL_SMETHOD(spa->rtp->stream[1]->ttl, reset);
        RTPP_LOG(spa->log, RTPP_LOG_INFO,
          "lookup on ports %d/%d, session timer restarted", spa->rtp->stream[0]->port,
          spa->rtp->stream[1]->port);
    } else {
        struct rtpp_hash_table_entry *hte;

        RTPP_DBG_ASSERT(cmd->cca.op == UPDATE);
        if (ulop->local_addr != NULL) {
            ulop->lia[0] = ulop->lia[1] = ulop->local_addr;
        }
        RTPP_LOG(cmd->glog, RTPP_LOG_INFO,
          "new %s/%s session %.*s, tag %.*s requested, type %s",
          SA_AF2STR(ulop->lia[0]), SA_AF2STR(ulop->lia[1]), FMTSTR(cmd->cca.call_id),
          FMTSTR(cmd->cca.from_tag), ulop->weak ? "weak" : "strong");
        if (cfsp->slowshutdown != 0) {
            RTPP_LOG(cmd->glog, RTPP_LOG_INFO,
              "proxy is in the deorbiting-burn mode, new session rejected");
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_SLOWSHTDN);
            goto err_undo_0;
        }
        if (cfsp->overload_prot.ecode != 0 &&
          CALL_METHOD(cfsp->rtpp_cmd_cf, chk_overload) != 0) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
              "proxy is overloaded, new session rejected");
            CALL_SMETHOD(cmd->reply, deliver_error, cfsp->overload_prot.ecode);
            goto err_undo_0;
        }

        /*
         * Session creation. If creation is requested with weak flag,
         * set weak[0].
         */
        struct rtpp_session_ctor_args sa = {
            .cfs = cfsp, .ccap = &cmd->cca, .dtime = cmd->dtime, .lia = ulop->lia,
            .weak = ulop->weak,
        };
        spa = rtpp_session_ctor(&sa);
        if (spa == NULL) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "can't create session");
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_LSTFAIL_2);
            goto err_undo_0;
        }

        rtpp_command_get_stats(cmd)->nsess_created.cnt++;

        hte = CALL_SMETHOD(cfsp->sessions_ht, append_str_refcnt, spa->call_id,
          spa->rcnt, NULL);
        if (hte == NULL) {
            handle_nomem(cmd, ECODE_NOMEM_5, spa);
            return (-1);
        }
        if (CALL_SMETHOD(cfsp->sessions_wrt, reg, spa->rcnt, spa->seuid) != 0) {
            CALL_SMETHOD(cfsp->sessions_ht, remove_str, spa->call_id, hte);
            handle_nomem(cmd, ECODE_NOMEM_8, spa);
            return (-1);
        }

        /*
         * Each session can consume up to 5 open file descriptors (2 RTP,
         * 2 RTCP and 1 logging) so that warn user when he is likely to
         * exceed 80% mark on hard limit.
         */
        sessions_active = CALL_SMETHOD(cfsp->sessions_wrt, get_length);
        if (sessions_active > (rtpp_rlim_max(cfsp->nofile) * 80 / (100 * 5)) &&
          atomic_load(&cfsp->nofile->warned) == 0) {
            atomic_store(&(cfsp->nofile->warned), 1);
            RTPP_LOG(cmd->glog, RTPP_LOG_WARN, "passed 80%% "
              "threshold on the open file descriptors limit (%d), "
              "consider increasing the limit using -L command line "
              "option", (int)rtpp_rlim_max(cfsp->nofile));
        }

        lport = spa->rtp->stream[0]->port;
        RTPP_LOG(spa->log, RTPP_LOG_INFO, "new session on %s port %d created, "
          "tag %.*s", AF2STR(ulop->pf), lport, FMTSTR(cmd->cca.from_tag));
        if (cfsp->record_all != 0) {
            const struct record_opts ropts = {.record_single_file = RSF_MODE_DFLT(cfsp)};
            handle_copy(cfsp, NULL, spa, 0, NULL, &ropts);
            handle_copy(cfsp, NULL, spa, 1, NULL, &ropts);
        }
        /* Save ref, it will be decref'd by the command disposal code */
        RTPP_DBG_ASSERT(cmd->sp == NULL);
        RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, spa);
        cmd->sp = spa;
    }

    if (cmd->cca.op == UPDATE) {
        if (spa->timeout_data != NULL) {
            RTPP_OBJ_DECREF(spa->timeout_data);
            spa->timeout_data = NULL;
        }
        if (ulop->notify_socket != NULL) {
            struct rtpp_tnotify_target *rttp;
            struct rtpp_sockaddr raddr = rtpp_command_get_raddr(cmd);

            rttp = CALL_METHOD(cfsp->rtpp_tnset_cf, lookup, ulop->notify_socket->s,
              (raddr.l > 0) ? sstosa(raddr.a) : NULL, (raddr.l > 0) ? cmd->laddr : NULL);
            if (rttp == NULL) {
                RTPP_LOG(spa->log, RTPP_LOG_ERR, "invalid socket name %.*s",
                  FMTSTR(ulop->notify_socket));
                ulop->notify_socket = NULL;
            } else {
                RTPP_LOG(spa->log, RTPP_LOG_INFO, "setting timeout handler");
                RTPP_DBG_ASSERT(ulop->notify_tag.s != NULL);
                spa->timeout_data = rtpp_timeout_data_ctor(rttp,
                  rtpp_str_fix(&ulop->notify_tag));
                if (spa->timeout_data == NULL) {
                    RTPP_LOG(spa->log, RTPP_LOG_ERR,
                      "setting timeout handler: ENOMEM");
                }
            }
        } else if (spa->timeout_data != NULL) {
            RTPP_OBJ_DECREF(spa->timeout_data);
            spa->timeout_data = NULL;
            RTPP_LOG(spa->log, RTPP_LOG_INFO, "disabling timeout handler");
        }
    }

    if (ulop->ia[0] != NULL && ulop->ia[1] != NULL) {
        CALL_SMETHOD(spa->rtp->stream[pidx], prefill_addr, &(ulop->ia[0]),
          cmd->dtime->mono);
        CALL_SMETHOD(spa->rtcp->stream[pidx], prefill_addr, &(ulop->ia[1]),
          cmd->dtime->mono);
    }
    if (ulop->onhold != 0) {
        CALL_SMETHOD(spa->rtp->stream[pidx], reg_onhold);
        CALL_SMETHOD(spa->rtcp->stream[pidx], reg_onhold);
    }
    spa->rtp->stream[pidx]->asymmetric = spa->rtcp->stream[pidx]->asymmetric = ulop->asymmetric;
    if (ulop->asymmetric) {
        CALL_SMETHOD(spa->rtp->stream[pidx], locklatch);
        CALL_SMETHOD(spa->rtcp->stream[pidx], locklatch);
    }
    if (spa->rtp->stream[pidx]->codecs != NULL) {
        free(spa->rtp->stream[pidx]->codecs);
        spa->rtp->stream[pidx]->codecs = NULL;
    }
    if (ulop->codecs != NULL) {
        spa->rtp->stream[pidx]->codecs = ulop->codecs;
        ulop->codecs = NULL;
    }
    spa->rtp->stream[NOT(pidx)]->ptime = ulop->requested_ptime;
    actor = CALL_SMETHOD(spa->rtp->stream[pidx], get_actor);
    if (ulop->requested_ptime > 0) {
        RTPP_LOG(spa->log, RTPP_LOG_INFO, "RTP packets from %s "
          "will be resized to %d milliseconds", actor, ulop->requested_ptime);
    } else if (spa->rtp->stream[pidx]->resizer != NULL) {
          RTPP_LOG(spa->log, RTPP_LOG_INFO, "Resizing of RTP "
          "packets from %s has been disabled", actor);
    }
    if (ulop->requested_ptime > 0) {
        if (spa->rtp->stream[pidx]->resizer != NULL) {
            rtp_resizer_set_ptime(spa->rtp->stream[pidx]->resizer, ulop->requested_ptime);
        } else {
            spa->rtp->stream[pidx]->resizer = rtp_resizer_new(ulop->requested_ptime);
        }
    } else if (spa->rtp->stream[pidx]->resizer != NULL) {
        rtp_resizer_free(cfsp->rtpp_stats, spa->rtp->stream[pidx]->resizer);
        spa->rtp->stream[pidx]->resizer = NULL;
    }

    RTPP_DBG_ASSERT(lport != 0);
    ulop->reply.port = lport;
    ulop->reply.ia = ulop->lia[0];
    if (cfsp->advaddr[0] != NULL) {
        if (cfsp->bmode != 0 && cfsp->advaddr[1] != NULL &&
          ulop->lia[0] == cfsp->bindaddr[1]) {
            ulop->reply.ia_ov = cfsp->advaddr[1];
        } else {
            ulop->reply.ia_ov = cfsp->advaddr[0];
        }
    }
    for (int i = 0; i < cmd->subc.n; i++) {
        struct rtpp_subc_ctx rsc = {
            .sessp = spa,
            .strmp_in = spa->rtp->stream[pidx],
            .strmp_out = spa->rtp->stream[NOT(pidx)],
            .subc_args = &(cmd->subc.args[i]),
            .resp = &(cmd->subc.res[i])
        };
        rsc.resp->result = cmd->after_success[i].handler(
          &cmd->after_success[i].args, &rsc);
        if (rsc.resp->result != 0)
            break;
    }
    ul_reply_port(cmd, &ulop->reply);
    return (0);

err_undo_0:
    return (-1);
}
