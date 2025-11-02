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
#include <assert.h>
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
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_async.h"
#include "commands/rpcpv1_copy.h"
#include "commands/rpcpv1_delete.h"
#include "rtpp_command_parse.h"
#include "commands/rpcpv1_play.h"
#include "rtpp_command_ecodes.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "commands/rpcpv1_record.h"
#include "commands/rpcpv1_norecord.h"
#include "rtpp_command_rcache.h"
#include "commands/rpcpv1_query.h"
#include "commands/rpcpv1_stats.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc.h"
#include "commands/rpcpv1_ver.h"
#include "rtpp_command_reply.h"
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
#include "rtpp_command_ctx.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_stats.h"

struct rtpp_command_priv {
    struct rtpp_command pub;
    struct rtpp_command_ctx ctx;
};

struct d_opts;

static void handle_info(const struct rtpp_cfg *, struct rtpp_command *);

struct create_listener_args {
    const struct rtpp_cfg *cfs;
    const struct sockaddr *ia;
    struct rtpp_socket **fds;
    int *port;
};

static enum rtpp_ptu_rval
create_listener(struct create_listener_args *ctap, unsigned int port, struct rtpp_socket **fdp)
{
    struct sockaddr_storage iac;
    struct rtpp_socket *fd;
    int so_rcvbuf;
    enum rtpp_ptu_rval rval = RTPP_PTU_BRKERR;

    fd = rtpp_socket_ctor(ctap->cfs->rtpp_proc_cf->netio,
        ctap->ia->sa_family, SOCK_DGRAM);
    if (fd == NULL) {
        RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "can't create %s socket",
            SA_AF2STR(ctap->ia));
        goto e0;
    }
    memcpy(&iac, ctap->ia, SA_LEN(ctap->ia));
    satosin(&iac)->sin_port = htons(port);
    if (CALL_SMETHOD(fd, bind2, sstosa(&iac), SA_LEN(ctap->ia)) != 0) {
        if (errno != EADDRINUSE && errno != EACCES) {
            RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "can't bind to the %s port %d",
                SA_AF2STR(ctap->ia), port);
        } else {
            rval = RTPP_PTU_ONEMORE;
        }
        goto e1;
    }
    if ((ctap->ia->sa_family == AF_INET) && (ctap->cfs->tos >= 0) &&
      (CALL_SMETHOD(fd, settos, ctap->cfs->tos) == -1))
        RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "unable to set TOS to %d", ctap->cfs->tos);
    so_rcvbuf = 256 * 1024;
    if (CALL_SMETHOD(fd, setrbuf, so_rcvbuf) == -1)
        RTPP_ELOG(ctap->cfs->glog, RTPP_LOG_ERR, "unable to set 256K receive buffer size");
    if (CALL_SMETHOD(fd, setnonblock) < 0)
        goto e1;
    CALL_SMETHOD(fd, settimestamp);
    *fdp = fd;
    return (RTPP_PTU_OK);
e1:
    RTPP_OBJ_DECREF(fd);
e0:
    return rval;
}

static int
create_twinlistener(unsigned int port, void *ap)
{
    int rval, i;
    struct create_listener_args *ctap;

    RTPP_DBG_ASSERT(port >= 1 && IS_VALID_PORT(port - 1));
    ctap = (struct create_listener_args *)ap;
    ctap->fds[0] = ctap->fds[1] = NULL;

    for (i = 0; i < 2; i++) {
        rval = create_listener(ctap, port, &(ctap->fds[i]));
        if (rval != RTPP_PTU_OK)
            goto failure;
        port++;
    }
    RTPP_DBG_ASSERT(port > 2 && IS_VALID_PORT(port - 2));
    *ctap->port = port - 2;
    return RTPP_PTU_OK;

failure:
    for (i = 0; i < 2; i++) {
        if (ctap->fds[i] == NULL)
            continue;
        RTPP_OBJ_DECREF(ctap->fds[i]);
        ctap->fds[i] = NULL;
    }
    return rval;
}

int
rtpp_create_listener(const struct rtpp_cfg *cfsp, const struct sockaddr *ia, int *port,
  struct rtpp_socket **fds)
{
    struct create_listener_args cta;
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

struct rtpp_command *
rtpp_command_ctor(const struct rtpp_cfg *cfsp, int controlfd,
  const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp, int umode)
{
    struct rtpp_command_priv *pvt;
    struct rtpp_command *cmd;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_command_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        return (NULL);
    }
    cmd = &(pvt->pub);
    pvt->ctx.controlfd = controlfd;
    pvt->ctx.cfs = cfsp;
    pvt->ctx.dtime.wall = dtime->wall;
    pvt->ctx.dtime.mono = dtime->mono;
    cmd->dtime = &pvt->ctx.dtime;
    pvt->ctx.csp = csp;
    cmd->glog = cfsp->glog;
    pvt->ctx.umode = umode;
    cmd->reply = rtpc_reply_ctor(&pvt->ctx);
    if (cmd->reply == NULL) {
        RTPP_OBJ_DECREF(cmd);
        return (NULL);
    }
    RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, cmd->reply);
    return (cmd);
}

void
rtpp_command_set_raddr(struct rtpp_command *cmd, const struct sockaddr *raddr, socklen_t rlen)
{
    struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);
    memcpy(&pvt->ctx.raddr, raddr, rlen);
    pvt->ctx.rlen = rlen;
}

struct rtpp_sockaddr
rtpp_command_get_raddr(const struct rtpp_command *cmd)
{
    struct rtpp_sockaddr raddr;
    const struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);
    raddr.a = &pvt->ctx.raddr;
    raddr.l = pvt->ctx.rlen;
    return (raddr);
}

struct rtpp_command_stats *
rtpp_command_get_stats(const struct rtpp_command *cmd)
{
    const struct rtpp_command_priv *pvt;

    PUB2PVT(cmd, pvt);
    return (pvt->ctx.csp);
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
                    RTPP_OBJ_DECREF(cmd);
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
            pvt->ctx.rlen = sizeof(pvt->ctx.raddr);
            lp = &pvt->ctx.rlen;
            raddr = sstosa(&pvt->ctx.raddr);
        }
        len = recvfrom(controlfd, bp, bsize - 1, 0, raddr, lp);
    }
    if (len == -1) {
        if (errno != EAGAIN && errno != EINTR)
            RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "can't read from control socket");
        if (cmd != NULL)
            RTPP_OBJ_DECREF(cmd);
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
        RTPP_OBJ_DECREF(cmd);
        return (NULL);
    }
    return (cmd);
}

#define ISAMPAMP(vp) ((vp)->len == 2 && (vp)->s[0] == '&' && (vp)->s[1] == '&')

static int
rtpp_command_guard_retrans(struct rtpp_command *cmd,
  struct rtpp_cmd_rcache *rcache_obj)
{
    size_t len;
    struct rtpp_command_priv *pvt;
    struct rtpp_cmd_rcache_entry *cres;

    PUB2PVT(cmd, pvt);
    cres = CALL_METHOD(rcache_obj, lookup, rtpp_str_fix(&pvt->ctx.cookie));
    if (cres == NULL) {
        RTPP_OBJ_BORROW(cmd, rcache_obj);
        pvt->ctx.rcache_obj = rcache_obj;
        return (0);
    }
    len = cres->reply->len;
    int r = rtpp_anetio_sendto_na(pvt->ctx.cfs->rtpp_proc_cf->netio, pvt->ctx.controlfd,
      cres->reply->s, len, 0, sstosa(&pvt->ctx.raddr), pvt->ctx.rlen, cres->rcnt);
    if (r != 0)
        RTPP_OBJ_DECREF(cres);
    pvt->ctx.csp->ncmds_rcvd.cnt--;
    pvt->ctx.csp->ncmds_rcvd_ndups.cnt++;
    return (1);
}

int
rtpp_command_split(struct rtpp_command *cmd, int len, int *rval,
  struct rtpp_cmd_rcache *rcache_obj)
{
    rtpp_str_const_t *ap;
    struct rtpp_command_priv *pvt;
    struct rtpp_command_args *cap;
    char mbuf[RTPP_CMD_BUFLEN];

    PUB2PVT(cmd, pvt);
    if (len > 0 && cmd->buf[len - 1] == '\n') {
        RTPP_LOG(pvt->ctx.cfs->glog, RTPP_LOG_DBUG, "received command \"%.*s\\n\"",
          len - 1, cmd->buf);
    } else {
        RTPP_LOG(pvt->ctx.cfs->glog, RTPP_LOG_DBUG, "received command \"%s\"",
          cmd->buf);
    }
    pvt->ctx.csp->ncmds_rcvd.cnt++;

    cap = &cmd->args;
    rtpp_strsplit(cmd->buf, mbuf, len, sizeof(mbuf));
    char *mp, *mp_next;
    ap = cap->v;
    for (mp = mbuf; mp != NULL && (mp - mbuf) < len; mp = mp_next) {
        rtpp_str_const_t tap;
        mp_next = memchr(mp, '\0', len - (mp - mbuf));
        if (mp_next == NULL) {
            tap.len = mbuf + len - mp;
        } else {
            tap.len = mp_next - mp;
            mp_next += 1;
        }
        if (tap.len == 0) {
            continue;
        }
        tap.s = cmd->buf + (mp - mbuf);
        size_t slen = strlen(tap.s);
        RTPP_DBG_ASSERT(slen <= tap.len);
        if (slen < tap.len) {
            /* \0 inside a parameter is not allowed */
            goto synerr;
        }
        *ap = tap;

        if (cap == &cmd->args) {
            /* Stream communication mode doesn't use cookie */
            if (pvt->ctx.umode != 0 && cap->c == 0 && pvt->ctx.cookie.s == NULL) {
                pvt->ctx.cookie = *ap;
                if (rtpp_command_guard_retrans(cmd, rcache_obj)) {
                    *rval = GET_CMD_OK;
                    return (1);
                }
                assert(CALL_SMETHOD(cmd->reply, appendf, "%.*s ", (int)ap->len, ap->s) == 0);
                CALL_SMETHOD(cmd->reply, commit);
                continue;
            }
        }

        if (ISAMPAMP(ap)) {
            if (cmd->subc.n == (MAX_SUBC_NUM - 1))
                goto synerr;
            ap->s = NULL;
            ap->len = 0;
            cap = &cmd->subc.args[cmd->subc.n];
            cmd->subc.n += 1;
            ap = cap->v;
            continue;
        }
        cap->c++;
        if (++ap >= &cap->v[RTPC_MAX_ARGC])
            goto synerr;
    }
    if (cmd->args.c < 1 || (pvt->ctx.umode != 0 && pvt->ctx.cookie.s == NULL)) {
        goto synerr;
    }
    for (int i = 0; i < cmd->subc.n; i++) {
        cap = &cmd->subc.args[i];
        if (cap->c < 1) {
            goto synerr;
        }
    }

    /* Step I: parse parameters that are common to all ops */
    if (rtpp_command_pre_parse(pvt->ctx.cfs, cmd) != 0) {
        /* Error reply is handled by the rtpp_command_pre_parse() */
        *rval = GET_CMD_INVAL;
        return (1);
    }

    return (0);
synerr:
    RTPP_LOG(pvt->ctx.cfs->glog, RTPP_LOG_ERR, "command syntax error");
    CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_1);
    *rval = GET_CMD_INVAL;
    return (1);

}

int
handle_command(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd)
{
    int i, verbose, rval;
    const char *cp;
    const char *recording_name;
    struct rtpp_session *spa;
    int norecord_all;

    spa = NULL;
    recording_name = NULL;
    norecord_all = 0;

    /* Step II: parse parameters that are specific to a particular op and run simple ops */
    switch (cmd->cca.op) {
    case VER_FEATURE:
        handle_ver_feature(cfsp, cmd);
        return 0;

    case GET_VER:
        /* This returns base version. */
        CALL_SMETHOD(cmd->reply, deliver_number, CPROTOVER);
        return 0;

    case DELETE_ALL:
        /* Delete all active sessions */
        RTPP_LOG(cfsp->glog, RTPP_LOG_INFO, "deleting all active sessions");
        CALL_SMETHOD(cfsp->sessions_wrt, purge);
        CALL_SMETHOD(cfsp->sessions_ht, purge);
        CALL_SMETHOD(cmd->reply, deliver_ok);
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
        recording_name = cmd->args.v[2].s;
        /* Fallthrough */
    case RECORD:
        cmd->cca.opts.record = rtpp_command_record_opts_parse(cfsp, cmd, &cmd->args);
        if (cmd->cca.opts.record == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "can't parse options");
            return 0;
        }
        RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, cmd->cca.opts.record);
        break;

    case NORECORD:
        if (cmd->args.v[0].s[1] == 'A' || cmd->args.v[0].s[1] == 'a') {
            if (cmd->args.v[0].s[2] != '\0') {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_2);
                return 0;
            }
            norecord_all = 1;
        } else {
            if (cmd->args.v[0].s[1] != '\0') {
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "command syntax error");
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_3);
                return 0;
            }
            norecord_all = 0;
        }
        break;

    case DELETE:
        /* D[w] call_id from_tag [to_tag] */
        cmd->cca.opts.delete = rtpp_command_del_opts_parse(cmd, &cmd->args);
        if (cmd->cca.opts.delete == NULL) {
            RTPP_LOG(cfsp->glog, RTPP_LOG_ERR, "can't parse options");
            return 0;
        }
        RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, cmd->cca.opts.delete);
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
        for (cp = cmd->args.v[0].s + 1; *cp != '\0'; cp++) {
            switch (*cp) {
            case 'v':
            case 'V':
                verbose = 1;
                break;

            default:
                RTPP_LOG(cfsp->glog, RTPP_LOG_ERR,
                  "STATS: unknown command modifier `%c'", *cp);
                CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_5);
                return 0;
            }
        }
        i = handle_get_stats(cfsp->rtpp_stats, cmd, verbose);
        if (i != 0) {
            CALL_SMETHOD(cmd->reply, deliver_error, i);
        }
        return 0;

    default:
        break;
    }

    for (int i = 0; i < cmd->subc.n; i++) {
        if (rtpp_subcommand_ul_opts_parse(cfsp, cmd, &cmd->subc.args[i],
          &cmd->after_success[i]) != 0) {
            if (cmd->cca.op == UPDATE || cmd->cca.op == LOOKUP)
                rtpp_command_ul_opts_free(cmd->cca.opts.ul);
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_SUBC);
            return 0;
        }
        RTPP_DBG_ASSERT(cmd->after_success[i].handler != NULL);
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
        i = handle_record(cfsp, cmd);
        break;

    case NORECORD:
        i = handle_norecord(cfsp, &cmd->cca, norecord_all);
        break;

    default:
        i = find_stream(cfsp, cmd->cca.call_id, cmd->cca.from_tag,
        cmd->cca.to_tag, &spa);
        if (i != -1) {
            if (cmd->cca.op != UPDATE)
            i = NOT(i);
            RTPP_DBG_ASSERT(cmd->sp == NULL);
            RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, spa);
            cmd->sp = spa;
        }
        break;
    }

    if (i == -1 && cmd->cca.op != UPDATE) {
        rtpp_str_t to_tag = cmd->cca.to_tag ? *cmd->cca.to_tag :
          (rtpp_str_t){.len = 4, .s = "NONE"};
        RTPP_LOG(cfsp->glog, RTPP_LOG_INFO,
          "%s request failed: session %.*s, tags %.*s/%.*s not found", cmd->cca.rname,
          (int)cmd->cca.call_id->len, cmd->cca.call_id->s, (int)cmd->cca.from_tag->len,
          cmd->cca.from_tag->s, (int)to_tag.len, to_tag.s);
        switch (cmd->cca.op) {
        case LOOKUP:
            rtpp_command_ul_opts_free(cmd->cca.opts.ul);
            ul_reply_port(cmd, NULL);
            return 0;

        case PLAY:
            rtpp_command_play_opts_free(cmd->cca.opts.play);
            break;

        case COPY:
        case RECORD:
            RTPP_DBG_ASSERT(CALL_SMETHOD(cmd->cca.opts.record->rcnt, peek) == 1);
            break;

        case DELETE:
            RTPP_DBG_ASSERT(CALL_SMETHOD(cmd->cca.opts.delete->rcnt, peek) == 1);
            break;

        default:
            RTPP_DBG_ASSERT(cmd->cca.opts.ptr == NULL);
            break;
        }
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_SESUNKN);
        return 0;
    }

    switch (cmd->cca.op) {
    case DELETE:
    case NORECORD:
        CALL_SMETHOD(cmd->reply, deliver_ok);
        break;

    case NOPLAY:
        CALL_SMETHOD(spa->rtp->stream[i], handle_noplay);
        CALL_SMETHOD(cmd->reply, deliver_ok);
        break;

    case PLAY:
        rtpp_command_play_handle(spa->rtp->stream[i], cmd, cfsp);
        break;

    case COPY:
        if (handle_copy(cfsp, cmd, spa, i, recording_name, cmd->cca.opts.record) != 0) {
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_CPYFAIL);
            return 0;
        }
    case RECORD:
        break;

    case QUERY:
        rval = handle_query(cfsp, cmd, spa->rtp, i);
        if (rval != 0) {
            CALL_SMETHOD(cmd->reply, deliver_error, rval);
        }
        break;

    case LOOKUP:
    case UPDATE:
        rtpp_command_ul_handle(cfsp, cmd, i);
        rtpp_command_ul_opts_free(cmd->cca.opts.ul);
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
    int aerr, i, load;
    unsigned long long packets_in, packets_out;
    unsigned long long sessions_created;
    int sessions_active, rtp_streams_active;
    const char *opts;

    opts = &cmd->args.v[0].s[1];
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
            CALL_SMETHOD(cmd->reply, deliver_error, ECODE_PARSE_7);
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
    rtp_streams_active = CALL_SMETHOD(cfsp->rtp_streams_wrt, get_length);
    aerr = CALL_SMETHOD(cmd->reply, appendf, "sessions created: %llu\nactive sessions: %d\n"
      "active streams: %d\npackets received: %llu\npackets transmitted: %llu\n",
      sessions_created, sessions_active, rtp_streams_active, packets_in, packets_out);
    if (load != 0 && aerr == 0) {
          aerr = CALL_SMETHOD(cmd->reply, appendf, "average load: %f\n",
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
    if (aerr == 0) {
        CALL_SMETHOD(cmd->reply, commit);
        CALL_SMETHOD(cmd->reply, deliver, 0);
    } else {
        CALL_SMETHOD(cmd->reply, deliver_error, ECODE_NOMEM_6);
    }
}
