/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_weakref.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_bindaddrs.h"
#include "rtpp_command.h"
#include "rtpp_command_copy.h"
#include "rtpp_command_private.h"
#include "rtpp_command_ul.h"
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
#include "rtpp_util.h"
#include "rtpp_ttl.h"

#define FREE_IF_NULL(p)	{if ((p) != NULL) {free(p); (p) = NULL;}}

struct ul_reply {
    struct sockaddr *ia;
    const char *ia_ov;
    int port;
};

struct ul_opts {
    int asymmetric;
    int weak;
    int requested_ptime;
    char *codecs;
    char *addr;
    char *port;
    struct sockaddr *ia[2];
    struct sockaddr *lia[2];

    struct ul_reply reply;
    
    int lidx;
    struct sockaddr *local_addr;
    char *notify_socket;
    char *notify_tag;
    int pf;
    int new_port;

    int onhold;
};

void
ul_reply_port(struct rtpp_command *cmd, struct ul_reply *ulr)
{
    int len, rport;
    char saddr[MAX_ADDR_STRLEN];

    if (ulr == NULL || ulr->ia == NULL || ishostnull(ulr->ia)) {
        rport = (ulr == NULL) ? 0 : ulr->port;
        len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d\n", rport);
    } else {
        if (ulr->ia_ov == NULL) {
            addr2char_r(ulr->ia, saddr, sizeof(saddr));
            len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d %s%s\n", ulr->port,
              saddr, (ulr->ia->sa_family == AF_INET) ? "" : " 6");
        } else {
            len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d %s%s\n", ulr->port,
              ulr->ia_ov, (ulr->ia->sa_family == AF_INET) ? "" : " 6");
        }
    }

    rtpc_doreply(cmd, cmd->buf_t, len, (ulr != NULL) ? 0 : 1);
}

static void
ul_opts_init(struct cfg *cf, struct ul_opts *ulop)
{

    ulop->asymmetric = (cf->stable->aforce != 0) ? 1 : 0;
    ulop->requested_ptime = -1;
    ulop->lia[0] = ulop->lia[1] = ulop->reply.ia = cf->stable->bindaddr[0];
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
rtpp_command_ul_opts_parse(struct cfg *cf, struct rtpp_command *cmd)
{
    int len, tpf, n, i;
    char c;
    char *cp, *t;
    const char *errmsg;
    struct sockaddr_storage tia;
    struct ul_opts *ulop;

    ulop = rtpp_zmalloc(sizeof(struct ul_opts));
    if (ulop == NULL) {
        reply_error(cmd, ECODE_NOMEM_1);
        goto err_undo_0;
    }
    ul_opts_init(cf, ulop);
    if (cmd->cca.op == UPDATE && cmd->argc > 6) {
        if (cmd->argc == 8) {
            ulop->notify_socket = cmd->argv[6];
            ulop->notify_tag = cmd->argv[7];
        } else {
            ulop->notify_socket = cmd->argv[5];
            ulop->notify_tag = cmd->argv[6];
            cmd->cca.to_tag = NULL;
        }
        len = url_unquote((uint8_t *)ulop->notify_tag, strlen(ulop->notify_tag));
        if (len == -1) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
              "command syntax error - invalid URL encoding");
            reply_error(cmd, ECODE_PARSE_10);
            goto err_undo_1;
        }
        ulop->notify_tag[len] = '\0';
    }
    ulop->addr = cmd->argv[2];
    ulop->port = cmd->argv[3];
    /* Process additional command modifiers */
    for (cp = cmd->argv[0] + 1; *cp != '\0'; cp++) {
        switch (*cp) {
        case 'a':
        case 'A':
            ulop->asymmetric = 1;
            break;

        case 'e':
        case 'E':
            if (ulop->lidx < 0 || cf->stable->bindaddr[1] == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_11);
                goto err_undo_1;
            }
            ulop->lia[ulop->lidx] = cf->stable->bindaddr[1];
            ulop->lidx--;
            break;

        case 'i':
        case 'I':
            if (ulop->lidx < 0 || cf->stable->bindaddr[1] == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_12);
                goto err_undo_1;
            }
            ulop->lia[ulop->lidx] = cf->stable->bindaddr[0];
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
            ulop->requested_ptime = strtol(cp + 1, &cp, 10);
            if (ulop->requested_ptime <= 0) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_13);
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
            if (t == cp) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_14);
                goto err_undo_1;
            }
            ulop->codecs = malloc(cp - t + 1);
            if (ulop->codecs == NULL) {
                reply_error(cmd, ECODE_NOMEM_2);
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
                reply_error(cmd, ECODE_PARSE_15);
                goto err_undo_1;
            }
            c = t[len];
            t[len] = '\0';
            ulop->local_addr = host2bindaddr(cf, t, tpf, &errmsg);
            if (ulop->local_addr == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "invalid local address: %s: %s", t, errmsg);
                reply_error(cmd, ECODE_INVLARG_1);
                goto err_undo_1;
            }
            t[len] = c;
            cp--;
            break;

        case 'r':
        case 'R':
            len = extractaddr(cp + 1, &t, &cp, &tpf);
            if (len == -1) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_16);
                goto err_undo_1;
            }
            c = t[len];
            t[len] = '\0';
            ulop->local_addr = alloca(sizeof(struct sockaddr_storage));
            n = resolve(ulop->local_addr, tpf, t, SERVICE, AI_PASSIVE);
            if (n != 0) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "invalid remote address: %s: %s", t, gai_strerror(n));
                reply_error(cmd, ECODE_INVLARG_2);
                goto err_undo_1;
            }
            if (local4remote(ulop->local_addr, satoss(ulop->local_addr)) == -1) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "can't find local address for remote address: %s", t);
                reply_error(cmd, ECODE_INVLARG_3);
                goto err_undo_1;
            }
            ulop->local_addr = addr2bindaddr(cf, ulop->local_addr, &errmsg);
            if (ulop->local_addr == NULL) {
                RTPP_LOG(cmd->glog, RTPP_LOG_ERR,
                  "invalid local address: %s", errmsg);
                reply_error(cmd, ECODE_INVLARG_4);
                goto err_undo_1;
            }
            t[len] = c;
            cp--;
            break;

        case 'n':
        case 'N':
            ulop->new_port = 1;
            break;

        default:
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "unknown command modifier `%c'",
              *cp);
            break;
        }
    }
    if (ulop->local_addr == NULL && ulop->lidx == 1 &&
      ulop->pf != ulop->lia[0]->sa_family) {
        /*
         * When there is no explicit direction specified via "E"/"I" and no
         * local/remote address provided either via "R" or "L" make sure we
         * pick up address that matches the address family of the stream.
         */
        ulop->local_addr = bindaddr4af(cf, ulop->pf);
        if (ulop->local_addr == NULL) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "cannot match local "
              "address for the %s session", AF2STR(ulop->pf));
            reply_error(cmd, ECODE_INVLARG_6);
            goto err_undo_1;
        }
    }
    if (ulop->addr != NULL && ulop->port != NULL && IS_IPSTR_VALID(ulop->addr, ulop->pf)) {
        n = resolve(sstosa(&tia), ulop->pf, ulop->addr, ulop->port, AI_NUMERICHOST);
        if (n == 0) {
            if (!ishostnull(sstosa(&tia))) {
                for (i = 0; i < 2; i++) {
                    ulop->ia[i] = malloc(SS_LEN(&tia));
                    if (ulop->ia[i] == NULL) {
                        reply_error(cmd, ECODE_NOMEM_3);
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
              ulop->pf, ulop->addr, ulop->port, gai_strerror(n));
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
    rtpp_command_ul_opts_free(cmd->cca.opts.ul);
    if (spa != NULL) {
        CALL_SMETHOD(spa->rcnt, decref);
    }
    reply_error(cmd, ecode);
}

int
rtpp_command_ul_handle(struct cfg *cf, struct rtpp_command *cmd, int sidx)
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
    if (sidx != -1) {
        RTPP_DBG_ASSERT(cmd->cca.op == UPDATE || cmd->cca.op == LOOKUP);
        spa = cmd->sp;
        fd = CALL_SMETHOD(spa->rtp->stream[sidx], get_skt);
        if (fd == NULL || ulop->new_port != 0) {
            if (ulop->local_addr != NULL) {
                spa->rtp->stream[sidx]->laddr = ulop->local_addr;
            }
            if (rtpp_create_listener(cf, spa->rtp->stream[sidx]->laddr, &lport, fds) == -1) {
                RTPP_LOG(spa->log, RTPP_LOG_ERR, "can't create listener");
                reply_error(cmd, ECODE_LSTFAIL_1);
                if (fd != NULL) {
                    CALL_SMETHOD(fd->rcnt, decref);
                }
                goto err_undo_0;
            }
            if (fd != NULL && ulop->new_port != 0) {
                RTPP_LOG(spa->log, RTPP_LOG_INFO,
                  "new port requested, releasing %d/%d, replacing with %d/%d",
                  spa->rtp->stream[sidx]->port, spa->rtcp->stream[sidx]->port, lport, lport + 1);
                CALL_METHOD(cf->stable->sessinfo, update, spa, sidx, fds);
            } else {
                CALL_METHOD(cf->stable->sessinfo, append, spa, sidx, fds);
            }
            CALL_SMETHOD(fds[0]->rcnt, decref);
            CALL_SMETHOD(fds[1]->rcnt, decref);
            spa->rtp->stream[sidx]->port = lport;
            spa->rtcp->stream[sidx]->port = lport + 1;
            if (spa->complete == 0) {
                cmd->csp->nsess_complete.cnt++;
                CALL_METHOD(spa->rtp->stream[0]->ttl, reset_with,
                  cf->stable->max_ttl);
                CALL_METHOD(spa->rtp->stream[1]->ttl, reset_with,
                  cf->stable->max_ttl);
            }
            spa->complete = 1;
        }
        if (fd != NULL) {
            CALL_SMETHOD(fd->rcnt, decref);
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
        CALL_METHOD(spa->rtp->stream[0]->ttl, reset);
        CALL_METHOD(spa->rtp->stream[1]->ttl, reset);
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
          "new %s/%s session %s, tag %s requested, type %s",
          SA_AF2STR(ulop->lia[0]), SA_AF2STR(ulop->lia[1]),
          cmd->cca.call_id, cmd->cca.from_tag, ulop->weak ? "weak" : "strong");
        if (cf->stable->slowshutdown != 0) {
            RTPP_LOG(cmd->glog, RTPP_LOG_INFO,
              "proxy is in the deorbiting-burn mode, new session rejected");
            reply_error(cmd, ECODE_SLOWSHTDN);
            goto err_undo_0;
        }
        if (rtpp_create_listener(cf, ulop->lia[0], &lport, fds) == -1) {
            RTPP_LOG(cmd->glog, RTPP_LOG_ERR, "can't create listener");
            reply_error(cmd, ECODE_LSTFAIL_2);
            goto err_undo_0;
        }

        /*
         * Session creation. If creation is requested with weak flag,
         * set weak[0].
         */
        spa = rtpp_session_ctor(cf->stable, &cmd->cca, cmd->dtime, ulop->lia,
          ulop->weak, lport, fds);
        CALL_SMETHOD(fds[0]->rcnt, decref);
        CALL_SMETHOD(fds[1]->rcnt, decref);
        if (spa == NULL) {
            handle_nomem(cmd, ECODE_NOMEM_4, NULL);
            return (-1);
        }

        hte = CALL_METHOD(cf->stable->sessions_ht, append_refcnt, spa->call_id,
          spa->rcnt);
        if (hte == NULL) {
            handle_nomem(cmd, ECODE_NOMEM_5, spa);
            return (-1);
        }
        if (CALL_METHOD(cf->stable->sessions_wrt, reg, spa->rcnt, spa->seuid) != 0) {
            CALL_METHOD(cf->stable->sessions_ht, remove, spa->call_id, hte);
            handle_nomem(cmd, ECODE_NOMEM_8, spa);
            return (-1);
        }

        cmd->csp->nsess_created.cnt++;

        /*
         * Each session can consume up to 5 open file descriptors (2 RTP,
         * 2 RTCP and 1 logging) so that warn user when he is likely to
         * exceed 80% mark on hard limit.
         */
        sessions_active = CALL_METHOD(cf->stable->sessions_wrt, get_length);
        if (sessions_active > (rtpp_rlim_max(cf) * 80 / (100 * 5)) &&
          cf->nofile_limit_warned == 0) {
            cf->nofile_limit_warned = 1;
            RTPP_LOG(cmd->glog, RTPP_LOG_WARN, "passed 80%% "
              "threshold on the open file descriptors limit (%d), "
              "consider increasing the limit using -L command line "
              "option", (int)rtpp_rlim_max(cf));
        }

        RTPP_LOG(spa->log, RTPP_LOG_INFO, "new session on %s port %d created, "
          "tag %s", AF2STR(ulop->pf), lport, cmd->cca.from_tag);
        if (cf->stable->record_all != 0) {
            handle_copy(cf, spa, 0, NULL, 0);
            handle_copy(cf, spa, 1, NULL, 0);
        }
        /* Save ref, it will be decref'd by the command disposal code */
        RTPP_DBG_ASSERT(cmd->sp == NULL);
        cmd->sp = spa;
    }

    if (cmd->cca.op == UPDATE) {
        if (!CALL_METHOD(cf->stable->rtpp_tnset_cf, isenabled) && ulop->notify_socket != NULL)
            RTPP_LOG(spa->log, RTPP_LOG_ERR, "must permit notification socket with -n");
        if (spa->timeout_data.notify_tag != NULL) {
            free(spa->timeout_data.notify_tag);
            spa->timeout_data.notify_tag = NULL;
        }
        if (ulop->notify_socket != NULL) {
            struct rtpp_tnotify_target *rttp;

            rttp = CALL_METHOD(cf->stable->rtpp_tnset_cf, lookup, ulop->notify_socket,
              (cmd->rlen > 0) ? sstosa(&cmd->raddr) : NULL, (cmd->rlen > 0) ? cmd->laddr : NULL);
            if (rttp == NULL) {
                RTPP_LOG(spa->log, RTPP_LOG_ERR, "invalid socket name %s", ulop->notify_socket);
                ulop->notify_socket = NULL;
            } else {
                RTPP_LOG(spa->log, RTPP_LOG_INFO, "setting timeout handler");
                spa->timeout_data.notify_target = rttp;
                spa->timeout_data.notify_tag = strdup(ulop->notify_tag);
            }
        } else if (spa->timeout_data.notify_target != NULL) {
            spa->timeout_data.notify_target = NULL;
            RTPP_LOG(spa->log, RTPP_LOG_INFO, "disabling timeout handler");
        }
    }

    if (ulop->ia[0] != NULL && ulop->ia[1] != NULL) {
        CALL_SMETHOD(spa->rtp->stream[pidx], prefill_addr, &(ulop->ia[0]),
          cmd->dtime);
        CALL_SMETHOD(spa->rtcp->stream[pidx], prefill_addr, &(ulop->ia[1]),
          cmd->dtime);
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
        rtp_resizer_free(cf->stable->rtpp_stats, spa->rtp->stream[pidx]->resizer);
        spa->rtp->stream[pidx]->resizer = NULL;
    }

    RTPP_DBG_ASSERT(lport != 0);
    ulop->reply.port = lport;
    ulop->reply.ia = ulop->lia[0];
    if (cf->stable->advaddr[0] != NULL) {
        if (cf->stable->bmode != 0 && cf->stable->advaddr[1] != NULL &&
          ulop->lia[0] == cf->stable->bindaddr[1]) {
            ulop->reply.ia_ov = cf->stable->advaddr[1];
        } else {
            ulop->reply.ia_ov = cf->stable->advaddr[0];
        }
    }
    ul_reply_port(cmd, &ulop->reply);
    rtpp_command_ul_opts_free(ulop);
    return (0);

err_undo_0:
    rtpp_command_ul_opts_free(ulop);
    return (-1);
}
