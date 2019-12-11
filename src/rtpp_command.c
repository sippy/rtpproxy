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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_debug.h"
#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_defines.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_refcnt.h"
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_async.h"
#include "rtpp_command_copy.h"
#include "rtpp_command_delete.h"
#include "rtpp_command_parse.h"
#include "rtpp_command_play.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_private.h"
#include "rtpp_command_record.h"
#include "rtpp_command_rcache.h"
#include "rtpp_command_query.h"
#include "rtpp_command_stats.h"
#include "rtpp_command_ul.h"
#include "rtpp_command_ver.h"
#include "rtpp_controlfd.h"
#include "rtpp_hash_table.h"
#include "rtpp_mallocs.h"
#include "rtpp_netio_async.h"
#include "rtpp_network.h"
#include "rtpp_pipe.h"
#include "rtpp_port_table.h"
#include "rtpp_stream.h"
#include "rtpp_session.h"
#include "rtpp_socket.h"
#include "rtpp_util.h"
#include "rtpp_stats.h"
#include "rtpp_weakref.h"
#include "rtpp_proc_async.h"

struct rtpp_command_priv {
    struct rtpp_command pub;
    const struct rtpp_cfg *cfs;
    int controlfd;
    const char *cookie;
    int umode;
    char buf_r[256];
    struct rtpp_cmd_rcache *rcache_obj;
    struct rtpp_timestamp dtime;
};

struct d_opts;

static int create_twinlistener(uint16_t, void *);
static void handle_info(const struct rtpp_cfg *, struct rtpp_command *);

struct create_twinlistener_args {
    const struct rtpp_cfg *cfs;
    const struct sockaddr *ia;
    struct rtpp_socket **fds;
    int *port;
};

static int
create_twinlistener(uint16_t port, void *ap)
{
    struct sockaddr_storage iac;
    int rval, i, so_rcvbuf;
    struct create_twinlistener_args *ctap;

    ctap = (struct create_twinlistener_args *)ap;

    ctap->fds[0] = ctap->fds[1] = NULL;

    rval = RTPP_PTU_BRKERR;
    for (i = 0; i < 2; i++) {
	ctap->fds[i] = rtpp_socket_ctor(ctap->ia->sa_family, SOCK_DGRAM);
	if (ctap->fds[i] == NULL) {
	    RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "can't create %s socket",
	      SA_AF2STR(ctap->ia));
	    goto failure;
	}
	memcpy(&iac, ctap->ia, SA_LEN(ctap->ia));
	satosin(&iac)->sin_port = htons(port);
	if (CALL_METHOD(ctap->fds[i], bind2, sstosa(&iac), SA_LEN(ctap->ia)) != 0) {
	    if (errno != EADDRINUSE && errno != EACCES) {
		RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "can't bind to the %s port %d",
		  SA_AF2STR(ctap->ia), port);
	    } else {
		rval = RTPP_PTU_ONEMORE;
	    }
	    goto failure;
	}
	port++;
	if ((ctap->ia->sa_family == AF_INET) && (ctap->cfs->tos >= 0) &&
	  (CALL_METHOD(ctap->fds[i], settos, ctap->cfs->tos) == -1))
	    RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "unable to set TOS to %d", ctap->cfs->tos);
	so_rcvbuf = 256 * 1024;
	if (CALL_METHOD(ctap->fds[i], setrbuf, so_rcvbuf) == -1)
	    RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "unable to set 256K receive buffer size");
        if (CALL_METHOD(ctap->fds[i], setnonblock) < 0)
            goto failure;
        CALL_METHOD(ctap->fds[i], settimestamp);
    }
    *ctap->port = port - 2;
    return RTPP_PTU_OK;

failure:
    for (i = 0; i < 2; i++)
	if (ctap->fds[i] != NULL) {
            RTPP_OBJ_DECREF(ctap->fds[i]);
	    ctap->fds[i] = NULL;
	}
    return rval;
}

int
rtpp_create_listener(const struct rtpp_cfg *cfsp, const struct sockaddr *ia, int *port,
  struct rtpp_socket **fds)
{
    struct create_twinlistener_args cta;
    int i;
    struct rtpp_port_table *rpp;

    memset(&cta, '\0', sizeof(cta));
    cta.cfs = cfsp;
    cta.fds = fds;
    cta.ia = ia;
    cta.port = port;

    for (i = 0; i < 2; i++)
        fds[i] = NULL;

    rpp = RTPP_PT_SELECT(cfsp, ia->sa_family);
    return (CALL_METHOD(rpp, get_port, create_twinlistener,
      &cta));
}

void
rtpc_doreply(struct rtpp_command *cmd, char *buf, int len, int errd)
{
    struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);

    if (len > 0 && buf[len - 1] == '\n') {
        RTPP_LOG(pvt->cfs->glog, RTPP_LOG_DBUG, "sending reply \"%.*s\\n\"",
          len - 1, buf);
    } else {
        RTPP_LOG(pvt->cfs->glog, RTPP_LOG_DBUG, "sending reply \"%.*s\"",
          len, buf);
    }
    if (pvt->umode == 0) {
        if (write(pvt->controlfd, buf, len) < 0) {
            RTPP_DBG_ASSERT(!IS_WEIRD_ERRNO(errno));
        }
    } else {
        if (pvt->cookie != NULL) {
            len = snprintf(pvt->buf_r, sizeof(pvt->buf_r), "%s %.*s", pvt->cookie,
              len, buf);
            buf = pvt->buf_r;
            CALL_METHOD(pvt->rcache_obj, insert, pvt->cookie, pvt->buf_r,
              cmd->dtime->mono);
        }
        rtpp_anetio_sendto(pvt->cfs->rtpp_proc_cf->netio, pvt->controlfd, buf,
          len, 0, sstosa(&cmd->raddr), cmd->rlen);
    }
    cmd->csp->ncmds_repld.cnt++;
    if (errd == 0) {
        cmd->csp->ncmds_succd.cnt++;
    } else {
        cmd->csp->ncmds_errs.cnt++;
    }
}

void
reply_number(struct rtpp_command *cmd, int number)
{
    int len;

    len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "%d\n", number);
    rtpc_doreply(cmd, cmd->buf_t, len, 0);
}

void
reply_ok(struct rtpp_command *cmd)
{

    reply_number(cmd, 0);
}

void
reply_error(struct rtpp_command *cmd,
  int ecode)
{
    int len;

    len = snprintf(cmd->buf_t, sizeof(cmd->buf_t), "E%d\n", ecode);
    rtpc_doreply(cmd, cmd->buf_t, len, 1);
}

void
free_command(struct rtpp_command *cmd)
{
    struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);
    if (pvt->rcache_obj != NULL) {
        RTPP_OBJ_DECREF(pvt->rcache_obj);
    }
    if (cmd->sp != NULL) {
        RTPP_OBJ_DECREF(cmd->sp);
    }
    free(pvt);
}

struct rtpp_command *
rtpp_command_ctor(const struct rtpp_cfg *cfsp, int controlfd,
  const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp, int umode)
{
    struct rtpp_command_priv *pvt;
    struct rtpp_command *cmd;

    pvt = rtpp_zmalloc(sizeof(struct rtpp_command_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    cmd = &(pvt->pub);
    pvt->controlfd = controlfd;
    pvt->cfs = cfsp;
    pvt->dtime.wall = dtime->wall;
    pvt->dtime.mono = dtime->mono;
    cmd->dtime = &pvt->dtime;
    cmd->csp = csp;
    cmd->glog = cfsp->glog;
    pvt->umode = umode;
    return (cmd);
}

struct rtpp_command *
get_command(const struct rtpp_cfg *cfsp, struct rtpp_ctrl_sock *rcsp, int controlfd, int *rval,
  const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp,
  struct rtpp_cmd_rcache *rcache_obj)
{
    char *bp;
    int len;
    struct rtpp_command *cmd;
    struct rtpp_command_priv *pvt;
    int umode = RTPP_CTRL_ISDG(rcsp);
    size_t bsize;
    socklen_t asize, *lp;
    struct sockaddr *raddr;

    cmd = rtpp_command_ctor(cfsp, controlfd, dtime, csp, umode);
    if (cmd == NULL) {
        bp = rcsp->emrg.buf;
        bsize = sizeof(rcsp->emrg.buf);
    } else {
        bp = cmd->buf;
        bsize = sizeof(cmd->buf);
    }
    if (umode == 0) {
        for (;;) {
            len = read(controlfd, bp, bsize - 1);
            if (len == 0) {
                RTPP_LOG(cfsp->glog, RTPP_LOG_DBUG,
                  "EOF before receiving any command data");
                if (cmd != NULL)
                    free_command(cmd);
                *rval = GET_CMD_EOF;
                return (NULL);
            }
            if (len != -1 || (errno != EAGAIN && errno != EINTR))
                break;
        }
    } else {
	PUB2PVT(cmd, pvt);
        if (cmd == NULL) {
            asize = sizeof(rcsp->emrg.addr);
            lp = &asize;
            raddr = sstosa(&rcsp->emrg.addr);
        } else {
            cmd->rlen = sizeof(cmd->raddr);
            lp = &cmd->rlen;
            raddr = sstosa(&cmd->raddr);
        }
        len = recvfrom(controlfd, bp, bsize - 1, 0, raddr, lp);
    }
    if (len == -1) {
        if (errno != EAGAIN && errno != EINTR)
            RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "can't read from control socket");
        if (cmd != NULL)
            free_command(cmd);
        *rval = GET_CMD_IOERR;
        return (NULL);
    }
    if (cmd == NULL) {
        *rval = GET_CMD_ENOMEM;
        csp->ncmds_rcvd.cnt++;
        csp->ncmds_errs.cnt++;
        return (NULL);
    }
    cmd->buf[len] = '\0';

    if (rtpp_command_split(cmd, len, rval, rcache_obj) != 0) {
        /* Error reply is handled by the rtpp_command_split() */
        free_command(cmd);
        return (NULL);
    }
    return (cmd);
}

#define ISAMPAMP(v) ((v)[0] == '&' && (v)[1] == '&' && (v)[2] == '\0')

static int
rtpp_command_guard_retrans(struct rtpp_command *cmd,
  struct rtpp_cmd_rcache *rcache_obj)
{
    size_t len;
    struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);
    if (CALL_METHOD(rcache_obj, lookup, pvt->cookie, pvt->buf_r,
      sizeof(pvt->buf_r)) == 1) {
        len = strlen(pvt->buf_r);
        rtpp_anetio_sendto(pvt->cfs->rtpp_proc_cf->netio, pvt->controlfd,
          pvt->buf_r, len, 0, sstosa(&cmd->raddr), cmd->rlen);
        cmd->csp->ncmds_rcvd.cnt--;
        cmd->csp->ncmds_rcvd_ndups.cnt++;
        return (1);
    }
    RTPP_OBJ_INCREF(rcache_obj);
    pvt->rcache_obj = rcache_obj;
    return (0);
}

int
rtpp_command_split(struct rtpp_command *cmd, int len, int *rval,
  struct rtpp_cmd_rcache *rcache_obj)
{
    char **ap;
    char *cp;
    struct rtpp_command_priv *pvt;
    struct rtpp_command_args *cap;

    PUB2PVT(cmd, pvt);
    if (len > 0 && cmd->buf[len - 1] == '\n') {
        RTPP_LOG(pvt->cfs->glog, RTPP_LOG_DBUG, "received command \"%.*s\\n\"",
          len - 1, cmd->buf);
    } else {
        RTPP_LOG(pvt->cfs->glog, RTPP_LOG_DBUG, "received command \"%s\"",
          cmd->buf);
    }
    cmd->csp->ncmds_rcvd.cnt++;

    cp = cmd->buf;
    cap = &cmd->args;
    for (ap = cap->v; (*ap = rtpp_strsep(&cp, "\r\n\t ")) != NULL;) {
        if (**ap != '\0') {
            if (cap == &cmd->args) {
                /* Stream communication mode doesn't use cookie */
                if (pvt->umode != 0 && cap->c == 0 && pvt->cookie == NULL) {
                    pvt->cookie = *ap;
                    if (rtpp_command_guard_retrans(cmd, rcache_obj)) {
                        *rval = GET_CMD_OK;
                        return (1);
                    }
                    continue;
                }
                if (ISAMPAMP(*ap)) {
                    *ap = NULL;
                    cap = &cmd->subc_args;
                    ap = cap->v;
                    continue;
                }
            }
            cap->c++;
            if (++ap >= &cap->v[RTPC_MAX_ARGC])
                goto etoomany;
        }
    }
    if (cmd->args.c < 1 || (pvt->umode != 0 && pvt->cookie == NULL) ||
      (cap == &cmd->subc_args && cap->c < 1)) {
etoomany:
        RTPP_LOG(pvt->cfs->glog, RTPP_LOG_ERR, "command syntax error");
        reply_error(cmd, ECODE_PARSE_1);
        *rval = GET_CMD_INVAL;
        return (1);
    }

    /* Step I: parse parameters that are common to all ops */
    if (rtpp_command_pre_parse(pvt->cfs, cmd) != 0) {
        /* Error reply is handled by the rtpp_command_pre_parse() */
        *rval = GET_CMD_INVAL;
        return (1);
    }

    return (0);
}

int
handle_command(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    int i, verbose, rval;
    char *cp;
    char *recording_name;
    struct rtpp_session *spa;
    int record_single_file;

    spa = NULL;
    recording_name = NULL;

    /* Step II: parse parameters that are specific to a particular op and run simple ops */
    switch (cmd->cca.op) {
    case VER_FEATURE:
        handle_ver_feature(cfsp, cmd);
        return 0;

    case GET_VER:
        /* This returns base version. */
        reply_number(cmd, CPROTOVER);
        return 0;

    case DELETE_ALL:
        /* Delete all active sessions */
        RTPP_LOG(cfsp->glog, RTPP_LOG_INFO, "deleting all active sessions");
        CALL_METHOD(cfsp->sessions_wrt, purge);
        CALL_METHOD(cfsp->sessions_ht, purge);
        reply_ok(cmd);
        return 0;

    case INFO:
        handle_info(cfsp, cmd);
        return 0;

    case PLAY:
        /*
         * P callid pname codecs from_tag to_tag
         *
         *   <codecs> could be either comma-separated list of supported
         *   payload types or word "session" (without quotes), in which
         *   case list saved on last session update will be used instead.
         */
        cmd->cca.opts.play = rtpp_command_play_opts_parse(cmd);
        if (cmd->cca.opts.play == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "can't parse options");
            return 0;
        }
        break;

    case COPY:
        recording_name = cmd->args.v[2];
        /* Fallthrough */
    case RECORD:
        if (cmd->args.v[0][1] == 'S' || cmd->args.v[0][1] == 's') {
            if (cmd->args.v[0][2] != '\0') {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_2);
                return 0;
            }
            record_single_file = RSF_MODE_DFLT(cfsp);
        } else {
            if (cmd->args.v[0][1] != '\0') {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "command syntax error");
                reply_error(cmd, ECODE_PARSE_3);
                return 0;
            }
            record_single_file = 0;
        }
        break;

    case DELETE:
        /* D[w] call_id from_tag [to_tag] */
        cmd->cca.opts.delete = rtpp_command_del_opts_parse(cmd);
        if (cmd->cca.opts.delete == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "can't parse options");
            return 0;
        }
        break;

    case UPDATE:
    case LOOKUP:
        cmd->cca.opts.ul = rtpp_command_ul_opts_parse(cfsp, cmd);
        if (cmd->cca.opts.ul == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "can't parse options");
            return 0;
        }
	break;

    case GET_STATS:
        verbose = 0;
        for (cp = cmd->args.v[0] + 1; *cp != '\0'; cp++) {
            switch (*cp) {
            case 'v':
            case 'V':
                verbose = 1;
                break;

            default:
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR,
                  "STATS: unknown command modifier `%c'", *cp);
                reply_error(cmd, ECODE_PARSE_5);
                return 0;
            }
        }
        i = handle_get_stats(cfsp->rtpp_stats, cmd, verbose);
        if (i != 0) {
            reply_error(cmd, i);
        }
        return 0;

    default:
        break;
    }

    /*
     * Record and delete need special handling since they apply to all
     * streams in the session.
     */
    switch (cmd->cca.op) {
    case DELETE:
	i = handle_delete(cfsp, &cmd->cca);
	break;

    case RECORD:
	i = handle_record(cfsp, &cmd->cca, record_single_file);
	break;

    default:
	i = find_stream(cfsp, cmd->cca.call_id, cmd->cca.from_tag,
	  cmd->cca.to_tag, &spa);
	if (i != -1) {
	    if (cmd->cca.op != UPDATE)
		i = NOT(i);
	    RTPP_DBG_ASSERT(cmd->sp == NULL);
	    cmd->sp = spa;
	}
	break;
    }

    if (i == -1 && cmd->cca.op != UPDATE) {
	RTPP_LOG(cfsp->glog, RTPP_LOG_INFO,
	  "%s request failed: session %s, tags %s/%s not found", cmd->cca.rname,
	  cmd->cca.call_id, cmd->cca.from_tag, cmd->cca.to_tag != NULL ? cmd->cca.to_tag : "NONE");
	switch (cmd->cca.op) {
	case LOOKUP:
	    rtpp_command_ul_opts_free(cmd->cca.opts.ul);
	    ul_reply_port(cmd, NULL);
	    return 0;

	case PLAY:
	    rtpp_command_play_opts_free(cmd->cca.opts.play);
	    break;

	default:
	    RTPP_DBG_ASSERT(cmd->cca.opts.ptr == NULL);
	    break;
	}
	reply_error(cmd, ECODE_SESUNKN);
	return 0;
    }

    switch (cmd->cca.op) {
    case DELETE:
    case RECORD:
	reply_ok(cmd);
	break;

    case NOPLAY:
	CALL_SMETHOD(spa->rtp->stream[i], handle_noplay);
	reply_ok(cmd);
	break;

    case PLAY:
        rtpp_command_play_handle(spa->rtp->stream[i], cmd);
	break;

    case COPY:
	if (handle_copy(cfsp, spa, i, recording_name, record_single_file) != 0) {
            reply_error(cmd, ECODE_CPYFAIL);
            return 0;
        }
	reply_ok(cmd);
	break;

    case QUERY:
	rval = handle_query(cfsp, cmd, spa->rtp, i);
	if (rval != 0) {
	    reply_error(cmd, rval);
	}
	break;

    case LOOKUP:
    case UPDATE:
	rtpp_command_ul_handle(cfsp, cmd, i);
	break;

    default:
	/* Programmatic error, should not happen */
	abort();
    }

    return 0;
}

static void
handle_info(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
#if 0
    struct rtpp_session *spa, *spb;
    char addrs[4][256];
    int brief;
#endif
    int len, i, load;
    char buf[1024 * 8];
    unsigned long long packets_in, packets_out;
    unsigned long long sessions_created;
    int sessions_active, rtp_streams_active;
    const char *opts;

    opts = &cmd->args.v[0][1];
#if 0
    brief = 0;
#endif
    load = 0;
    for (i = 0; opts[i] != '\0'; i++) {
        switch (opts[i]) {
        case 'b':
        case 'B':
#if 0
            brief = 1;
#endif
            break;

        case 'l':
        case 'L':
            load = 1;
            break;

        default:
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "command syntax error");
            reply_error(cmd, ECODE_PARSE_7);
            return;
        }
    }

    packets_in = CALL_SMETHOD(cfsp->rtpp_stats, getlvalbyname, "npkts_rcvd");
    packets_out = CALL_SMETHOD(cfsp->rtpp_stats, getlvalbyname, "npkts_relayed") +
      CALL_SMETHOD(cfsp->rtpp_stats, getlvalbyname, "npkts_played");
    sessions_created = CALL_SMETHOD(cfsp->rtpp_stats, getlvalbyname,
      "nsess_created");
    sessions_active = sessions_created - CALL_SMETHOD(cfsp->rtpp_stats,
      getlvalbyname, "nsess_destroyed");
    rtp_streams_active = CALL_METHOD(cfsp->rtp_streams_wrt, get_length);
    len = snprintf(buf, sizeof(buf), "sessions created: %llu\nactive sessions: %d\n"
      "active streams: %d\npackets received: %llu\npackets transmitted: %llu\n",
      sessions_created, sessions_active, rtp_streams_active, packets_in, packets_out);
    if (load != 0) {
          len += snprintf(buf + len, sizeof(buf) - len, "average load: %f\n",
            CALL_METHOD(cfsp->rtpp_cmd_cf, get_aload));
    }
#if 0
XXX this needs work to fix it after rtp/rtcp split 
    for (i = 0; i < cfsp->nsessions && brief == 0; i++) {
        spa = cfsp->sessions[i];
        if (spa == NULL || spa->stream[0]->sidx != i)
            continue;
        /* RTCP twin session */
        if (spa->rtcp == NULL) {
            spb = spa->rtp;
            buf[len++] = '\t';
        } else {
            spb = spa->rtcp;
            buf[len++] = '\t';
            buf[len++] = 'C';
            buf[len++] = ' ';
        }

        addr2char_r(spb->laddr[1], addrs[0], sizeof(addrs[0]));
        if (spb->addr[1] == NULL) {
            strcpy(addrs[1], "NONE");
        } else {
            sprintf(addrs[1], "%s:%d", addr2char(spb->addr[1]),
              addr2port(spb->addr[1]));
        }
        addr2char_r(spb->laddr[0], addrs[2], sizeof(addrs[2]));
        if (spb->addr[0] == NULL) {
            strcpy(addrs[3], "NONE");
        } else {
            sprintf(addrs[3], "%s:%d", addr2char(spb->addr[0]),
              addr2port(spb->addr[0]));
        }

        len += snprintf(buf + len, sizeof(buf) - len,
          "%s/%s: caller = %s:%d/%s, callee = %s:%d/%s, "
          "stats = %lu/%lu/%lu/%lu, ttl = %d/%d\n",
          spb->call_id, spb->tag, addrs[0], spb->stream[1]->port, addrs[1],
          addrs[2], spb->stream[0]->port, addrs[3], spa->pcount[0], spa->pcount[1],
          spa->pcount[2], spa->pcount[3], spb->ttl[0], spb->ttl[1]);
        if (len + 512 > sizeof(buf)) {
            rtpc_doreply(cmd, buf, len);
            len = 0;
        }
    }
#endif
    if (len > 0) {
        rtpc_doreply(cmd, buf, len, 0);
    }
}
