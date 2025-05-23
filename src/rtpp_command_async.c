/*
 * Copyright (c) 2010 Sippy Software, Inc., http://www.sippysoft.com
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

#if defined(LINUX_XXX) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* pthread_setname_np() */
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_cfg.h"
#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_time.h"
#include "rtpp_command.h"
#include "rtpp_command_stats.h"
#include "rtpp_command_async.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_rcache.h"
#include "rtpp_command_stream.h"
#include "rtpp_network.h"
#include "rtpp_netio_async.h"
#include "rtpp_mallocs.h"
#include "rtpp_stats.h"
#include "rtpp_list.h"
#include "rtpp_controlfd.h"
#include "rtpp_locking.h"
#include "rtpp_util.h"
#include "rtpp_threads.h"
#include "rtpp_proc_async.h"

#define RTPC_MAX_CONNECTIONS 100

struct rtpp_cmd_pollset {
    struct pollfd *pfds;
    int pfds_used;
    struct rtpp_cmd_connection *rccs[RTPC_MAX_CONNECTIONS + 1];
    pthread_mutex_t pfds_mutex;
};

struct rtpp_cmd_accptset {
    struct pollfd *pfds;
    struct rtpp_ctrl_sock **csocks;
    int pfds_used;
};

struct rtpp_cmd_async_cf {
    struct rtpp_cmd_async pub;
    pthread_t thread_id;
    pthread_t acpt_thread_id;
    pthread_mutex_t cmd_mutex;
    int clock_tick;
    double tused;
    int tstate_queue;
    int tstate_acceptor;
    int acceptor_started;
    int overload;
#if 0
    struct recfilter average_load;
#endif
    struct rtpp_command_stats cstats;
    struct rtpp_cmd_pollset pset;
    int wakefds[2];
    struct rtpp_cmd_accptset aset;
    struct rtpp_cfg *cf_save;
    struct rtpp_cmd_rcache *rcache;
};

static double rtpp_command_async_get_aload(struct rtpp_cmd_async *);
static int rtpp_command_async_wakeup(struct rtpp_cmd_async *, int);
static void rtpp_command_async_reg_overload(struct rtpp_cmd_async *, int);
static int rtpp_command_async_chk_overload(struct rtpp_cmd_async *);
static void rtpp_command_async_dtor(struct rtpp_cmd_async *);

static void
init_cstats(struct rtpp_stats *sobj, struct rtpp_command_stats *csp)
{

    csp->ncmds_rcvd.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "ncmds_rcvd");
    csp->ncmds_rcvd_ndups.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "ncmds_rcvd_ndups");
    csp->ncmds_succd.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "ncmds_succd");
    csp->ncmds_errs.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "ncmds_errs");
    csp->ncmds_repld.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "ncmds_repld");

    csp->nsess_complete.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "nsess_complete");
    csp->nsess_created.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "nsess_created");

    csp->nplrs_created.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "nplrs_created");
    csp->nplrs_destroyed.cnt_idx = CALL_SMETHOD(sobj, getidxbyname, "nplrs_destroyed");
}

#define FLUSH_CSTAT(sobj, st)    { \
    if ((st).cnt > 0) { \
        CALL_SMETHOD(sobj, updatebyidx, (st).cnt_idx, (st).cnt); \
        (st).cnt = 0; \
    } \
}

static void
flush_cstats(struct rtpp_stats *sobj, struct rtpp_command_stats *csp)
{

    FLUSH_CSTAT(sobj, csp->ncmds_rcvd);
    FLUSH_CSTAT(sobj, csp->ncmds_rcvd_ndups);
    FLUSH_CSTAT(sobj, csp->ncmds_succd);
    FLUSH_CSTAT(sobj, csp->ncmds_errs);
    FLUSH_CSTAT(sobj, csp->ncmds_repld);

    FLUSH_CSTAT(sobj, csp->nsess_complete);
    FLUSH_CSTAT(sobj, csp->nsess_created);

    FLUSH_CSTAT(sobj, csp->nplrs_created);
    FLUSH_CSTAT(sobj, csp->nplrs_destroyed);
}

static int
accept_connection(const struct rtpp_cfg *cfsp, struct rtpp_ctrl_sock *rcsp,
  struct sockaddr *rap)
{
    int controlfd;
    socklen_t rlen;

    rlen = rtpp_csock_addrlen(rcsp);
    assert(rlen > 0);
    controlfd = accept(rcsp->controlfd_in, rap, &rlen);
    if (controlfd == -1) {
        if (errno != EWOULDBLOCK) {
            RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR,
              "can't accept connection on control socket");
        }
        return (-1);
    }
    return (controlfd);
}

static int
process_commands(struct rtpp_ctrl_sock *csock, const struct rtpp_cfg *cfsp, int controlfd,
  const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp,
  struct rtpp_stats *rsc, struct rtpp_cmd_rcache *rcp)
{
    int i, rval;
    struct rtpp_command *cmd;
    int umode;

    umode = RTPP_CTRL_ISDG(csock);
    i = 0;
    do {
again:
        cmd = get_command(cfsp, csock, controlfd, &rval, dtime, csp, rcp);
        if (cmd == NULL) {
            switch (rval) {
            case GET_CMD_OK:
            case GET_CMD_ENOMEM:
                /*
                 * get_command() failed with error other than I/O error
                 * or something, there might be some good commands in
                 * the queue.
                 */
                goto again;
            case GET_CMD_EOF:
                goto out;
            }
            i = -1;
        } else {
            cmd->laddr = sstosa(&csock->bindaddr);
            if (cmd->cca.op == GET_STATS || cmd->cca.op == INFO) {
                flush_cstats(rsc, csp);
            }
            if (cmd->no_glock == 0) {
                pthread_mutex_lock(&(cfsp->locks->glob));
            }
            i = handle_command(cfsp, cmd);
            if (cmd->no_glock == 0) {
                pthread_mutex_unlock(&(cfsp->locks->glob));
            }
            RTPP_OBJ_DECREF(cmd);
        }
    } while (i == 0 && umode != 0);
out:
    return (i);
}

static int
process_commands_stream(const struct rtpp_cfg *cfsp, struct rtpp_cmd_connection *rcc,
  const struct rtpp_timestamp *dtime, struct rtpp_command_stats *csp, struct rtpp_stats *rsc)
{
    int rval;
    struct rtpp_command *cmd;

    rval = rtpp_command_stream_doio(cfsp, rcc);
    if (rval <= 0) {
        return (-1);
    }
    do {
again:
        cmd = rtpp_command_stream_get(cfsp, rcc, &rval, dtime, csp);
        if (cmd == NULL) {
            switch (rval) {
            case GET_CMD_EAGAIN:
                return (0);
            case GET_CMD_OK:
            case GET_CMD_INVAL:
            case GET_CMD_ENOMEM:
                goto again;
            default:
                return (-1);
            }
        }
        cmd->laddr = sstosa(&rcc->csock->bindaddr);
        if (cmd->cca.op == GET_STATS || cmd->cca.op == INFO) {
            flush_cstats(rsc, csp);
        }
        if (cmd->no_glock == 0) {
            pthread_mutex_lock(&(cfsp->locks->glob));
        }
        rval = handle_command(cfsp, cmd);
        if (cmd->no_glock == 0) {
            pthread_mutex_unlock(&(cfsp->locks->glob));
        }
        RTPP_OBJ_DECREF(cmd);
    } while (rval == 0);
    return (rval);
}

static struct rtpp_cmd_connection *
rtpp_cmd_connection_ctor(int controlfd_in, int controlfd_out,
  struct rtpp_ctrl_sock *csock, struct sockaddr *rap)
{
    struct rtpp_cmd_connection *rcc;

    rcc = rtpp_zmalloc(sizeof(struct rtpp_cmd_connection));
    if (rcc == NULL) {
        return (NULL);
    }
    rcc->controlfd_in = controlfd_in;
    rcc->controlfd_out = controlfd_out;
    rcc->csock = csock;
    if (rap != NULL && RTPP_CTRL_ISUNIX(csock) == 0) {
        rcc->rlen = SA_LEN(rap);
        memcpy(&rcc->raddr, rap, rcc->rlen);
    }
    return (rcc);
}

void
rtpp_cmd_connection_dtor(struct rtpp_cmd_connection *rcc)
{

    if (rcc->controlfd_in != rcc->csock->controlfd_in) {
        close(rcc->controlfd_in);
        if (rcc->controlfd_out != rcc->controlfd_in) {
            close(rcc->controlfd_out);
        }
    }
    free(rcc);
}

static void
rtpp_cmd_acceptor_run(void *arg)
{
    struct rtpp_cmd_async_cf *cmd_cf;
    struct pollfd *tp;
    struct rtpp_cmd_pollset *psp;
    struct rtpp_cmd_accptset *asp;
    struct rtpp_cmd_connection *rcc;
    int nready, controlfd, i, tstate;
    struct sockaddr_storage raddr;

    cmd_cf = (struct rtpp_cmd_async_cf *)arg;
    psp = &cmd_cf->pset;
    asp = &cmd_cf->aset;

    for (;;) {
#ifndef LINUX_XXX
        /*
         * On most decent OSes but Linux close()ing file descriptor in
         * parent thread would wake up poll most of the time, however
         * once in a while it wouldn't. This is why we don't use INFTIM
         * below.
         */
        nready = poll(asp->pfds, asp->pfds_used, 1000);
#else
	nready = poll(asp->pfds, asp->pfds_used, 100);
#endif
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        tstate = cmd_cf->tstate_acceptor;
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);
        if (tstate == TSTATE_CEASE) {
            break;
        }
        if (nready <= 0)
            continue;
        for (i = 0; i < asp->pfds_used; i++) {
            if ((asp->pfds[i].revents & POLLIN) == 0) {
                continue;
            }
            controlfd = accept_connection(CONST(cmd_cf->cf_save), asp->csocks[i],
              sstosa(&raddr));
            if (controlfd < 0) {
                continue;
            }
            if (rtpp_command_async_wakeup(&cmd_cf->pub, 1) < 0) {
                /*
		 * We cannot proceed if proc cannot be waked,
		 * the pfds_mutex might remain locked forever.
		 */
                close(controlfd);
                continue;
            }
            pthread_mutex_lock(&psp->pfds_mutex);
            pthread_mutex_unlock(&cmd_cf->cmd_mutex);
            if (psp->pfds_used >= RTPC_MAX_CONNECTIONS) {
                pthread_mutex_unlock(&psp->pfds_mutex);
                close(controlfd);
                continue;
            }
            tp = realloc(psp->pfds, sizeof(struct pollfd) * (psp->pfds_used + 1));
            if (tp == NULL) {
                pthread_mutex_unlock(&psp->pfds_mutex);
                close(controlfd); /* Yeah, sorry, please try later */
                continue;
            }
            psp->pfds = tp;
            rcc = rtpp_cmd_connection_ctor(controlfd, controlfd, asp->csocks[i],
              sstosa(&raddr));
            if (rcc == NULL) {
                pthread_mutex_unlock(&psp->pfds_mutex);
                close(controlfd); /* Yeah, sorry, please try later */
                continue;
            }
            psp->pfds[psp->pfds_used].fd = controlfd;
            psp->pfds[psp->pfds_used].events = POLLIN | POLLERR | POLLHUP;
            psp->pfds[psp->pfds_used].revents = 0;
            psp->rccs[psp->pfds_used] = rcc;
            psp->pfds_used++;
            pthread_mutex_unlock(&psp->pfds_mutex);
            rtpp_command_async_wakeup(&cmd_cf->pub, 0);
        }
    }
}

static void
rtpp_cmd_queue_run(void *arg)
{
    struct rtpp_cmd_async_cf *cmd_cf;
    struct rtpp_cmd_pollset *psp;
    int i, nready, rval;
    struct rtpp_timestamp sptime;
    struct rtpp_command_stats *csp;
    struct rtpp_stats *rtpp_stats_cf;

    cmd_cf = (struct rtpp_cmd_async_cf *)arg;
    rtpp_stats_cf = cmd_cf->cf_save->rtpp_stats;
    csp = &cmd_cf->cstats;

    psp = &cmd_cf->pset;

    for (;;) {
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        if (cmd_cf->tstate_queue != TSTATE_RUN) {
            pthread_mutex_unlock(&cmd_cf->cmd_mutex);
            break;
        }
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);
        pthread_mutex_lock(&psp->pfds_mutex);
        nready = poll(psp->pfds, psp->pfds_used, INFTIM);
        if (nready == 0) {
            pthread_mutex_unlock(&psp->pfds_mutex);
            continue;
        }
        if (nready < 0 && errno == EINTR) {
            pthread_mutex_unlock(&psp->pfds_mutex);
            continue;
        }
        if (nready > 0) {
            for (i = 0; i < psp->pfds_used; i++) {
                if (i == 0) {
                    unsigned int dummy;
                    if (psp->pfds[i].revents & POLLIN) {
                        read(psp->pfds[i].fd, &dummy, sizeof(dummy));
                    }
                    continue;
                }
again:
                if ((psp->pfds[i].revents & (POLLERR | POLLHUP)) != 0) {
                    if (RTPP_CTRL_ACCEPTABLE(psp->rccs[i]->csock)) {
                        goto closefd;
                    }
                    if (psp->rccs[i]->csock->type == RTPC_STDIO && (psp->pfds[i].revents & POLLIN) == 0) {
                        goto closefd;
                    }
                }
                if ((psp->pfds[i].revents & POLLIN) == 0) {
                    continue;
                }
                rtpp_timestamp_get(&sptime);
                if (RTPP_CTRL_ISSTREAM(psp->rccs[i]->csock)) {
                    rval = process_commands_stream(CONST(cmd_cf->cf_save), psp->rccs[i], &sptime, csp, rtpp_stats_cf);
                } else {
                    rval = process_commands(psp->rccs[i]->csock, CONST(cmd_cf->cf_save), psp->pfds[i].fd,
                      &sptime, csp, rtpp_stats_cf, cmd_cf->rcache);
                }
                /*
                 * Shut down non-datagram sockets that got I/O error
                 * and also all non-continuous UNIX sockets are recycled
                 * after each use.
                 */
                if (!RTPP_CTRL_ISDG(psp->rccs[i]->csock) && (rval == -1 || !RTPP_CTRL_ISSTREAM(psp->rccs[i]->csock))) {
closefd:
                    if (psp->rccs[i]->csock->type == RTPC_STDIO && psp->rccs[i]->csock->exit_on_close != 0) {
                        cmd_cf->cf_save->slowshutdown = 1;
                    }
                    rtpp_cmd_connection_dtor(psp->rccs[i]);
                    psp->pfds_used--;
                    if (psp->pfds_used > 0 && i < psp->pfds_used) {
                        memmove(&psp->pfds[i], &psp->pfds[i + 1],
                          (psp->pfds_used - i) * sizeof(struct pollfd));
                        memmove(&psp->rccs[i], &psp->rccs[i + 1],
                          (psp->pfds_used - i) * sizeof(struct rtpp_ctrl_connection *));
                        goto again;
                    }
                }
            }
        }
        pthread_mutex_unlock(&psp->pfds_mutex);
        if (nready > 0) {
            rtpp_anetio_pump(cmd_cf->cf_save->rtpp_proc_cf->netio);
        }
        flush_cstats(rtpp_stats_cf, csp);
    }
}

static double
rtpp_command_async_get_aload(struct rtpp_cmd_async *pub)
{
#if 0
    double aload;
    struct rtpp_cmd_async_cf *cmd_cf;

    PUB2PVT(pub, cmd_cf);

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    aload = cmd_cf->average_load.lastval;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    return (aload);
#else
    return (0);
#endif
}

static int
rtpp_command_async_wakeup(struct rtpp_cmd_async *pub, int keep_locked)
{
    int old_clock;
    struct rtpp_cmd_async_cf *cmd_cf;

    PUB2PVT(pub, cmd_cf);

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    old_clock = cmd_cf->clock_tick;
    cmd_cf->clock_tick++;
    if (!keep_locked)
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    /* notify worker thread */
    if (write(cmd_cf->wakefds[0], &old_clock, sizeof(old_clock + 1)) <= 0) {
	if (keep_locked)
            pthread_mutex_unlock(&cmd_cf->cmd_mutex);
        return (-1);
    }

    return (old_clock);
}

static void
rtpp_command_async_reg_overload(struct rtpp_cmd_async *pub, int overload)
{
    struct rtpp_cmd_async_cf *cmd_cf;

    PUB2PVT(pub, cmd_cf);

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    cmd_cf->overload = overload;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);
}

static int
rtpp_command_async_chk_overload(struct rtpp_cmd_async *pub)
{
    struct rtpp_cmd_async_cf *cmd_cf;
    int rval;

    PUB2PVT(pub, cmd_cf);

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    rval = cmd_cf->overload;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);
    return (rval);
}

static int
init_pollset(const struct rtpp_cfg *cfsp, struct rtpp_cmd_pollset *psp, int wakefd)
{
    struct rtpp_ctrl_sock *ctrl_sock;
    int pfds_used, i;

    ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
    for (pfds_used = 1; ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        if (RTPP_CTRL_ACCEPTABLE(ctrl_sock))
            continue;
        pfds_used++;
    }
    psp->pfds = malloc(sizeof(struct pollfd) * pfds_used);
    if (psp->pfds == NULL) {
        return (-1);
    }
    if (pthread_mutex_init(&psp->pfds_mutex, NULL) != 0) {
        goto e1;
    }
    psp->pfds_used = pfds_used;
    if (psp->pfds_used == 0) {
        return (0);
    }
    psp->pfds[0].fd = wakefd;
    psp->pfds[0].events = POLLIN;
    psp->pfds[0].revents = 0;
    psp->rccs[0] = NULL;
    ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
    for (i = 1; ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        if (RTPP_CTRL_ACCEPTABLE(ctrl_sock))
            continue;
        psp->pfds[i].fd = ctrl_sock->controlfd_in;
        psp->pfds[i].events = POLLIN;
        psp->pfds[i].revents = 0;
        psp->rccs[i] = rtpp_cmd_connection_ctor(ctrl_sock->controlfd_in, 
          ctrl_sock->controlfd_out, ctrl_sock, NULL);
        if (psp->rccs[i] == NULL) {
            int j;

            for (j = i - 1; j >= 0; j --)
                rtpp_cmd_connection_dtor(psp->rccs[j]);
            goto e1;
        }
        i++;
    }
    if (i == 2 && RTPP_CTRL_ISSTREAM(psp->rccs[1]->csock)) {
        psp->rccs[1]->csock->exit_on_close = 1;
    }
    return (0);
e1:
    free(psp->pfds);
    return (-1);
}

static void
free_pollset(struct rtpp_cmd_pollset *psp)
{
    int i;

    for (i = 1; i < psp->pfds_used; i ++) {
        rtpp_cmd_connection_dtor(psp->rccs[i]);
    }
    free(psp->pfds);
}

static int
init_accptset(const struct rtpp_cfg *cfsp, struct rtpp_cmd_accptset *asp)
{
    int i, pfds_used;
    struct rtpp_ctrl_sock *ctrl_sock;

    pfds_used = 0;
    ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
    for (pfds_used = 0; ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        if (RTPP_CTRL_ACCEPTABLE(ctrl_sock) == 0)
            continue;
        pfds_used++;
    }
    if (pfds_used == 0) {
        return (0);
    }

    asp->pfds = malloc(sizeof(struct pollfd) * pfds_used);
    if (asp->pfds == NULL) {
        return (-1);
    }
    asp->pfds_used = pfds_used;
    asp->csocks = malloc(sizeof(struct rtpp_ctrl_sock) * pfds_used);
    if (asp->csocks == NULL) {
        free(asp->pfds);
        return (-1);
    }
    ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
    for (i = 0; i < asp->pfds_used; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        if (RTPP_CTRL_ACCEPTABLE(ctrl_sock) == 0)
            continue;
        asp->pfds[i].fd = ctrl_sock->controlfd_in;
        asp->pfds[i].events = POLLIN;
        asp->pfds[i].revents = 0;
        asp->csocks[i] = ctrl_sock;
        i++;
    }
    return (pfds_used);
}

static void
free_accptset(struct rtpp_cmd_accptset *asp)
{
    if (asp->pfds_used > 0) {
        free(asp->csocks);
        free(asp->pfds);
    }
}

struct rtpp_cmd_async *
rtpp_command_async_ctor(struct rtpp_cfg *cfsp)
{
    struct rtpp_cmd_async_cf *cmd_cf;
    int need_acptr, i;

    cmd_cf = rtpp_zmalloc(sizeof(*cmd_cf));
    if (cmd_cf == NULL)
        goto e0;

    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, cmd_cf->wakefds) != 0)
        goto e1;

    if (init_pollset(cfsp, &cmd_cf->pset, cmd_cf->wakefds[1]) == -1) {
        goto e2;
    }
    need_acptr = init_accptset(cfsp, &cmd_cf->aset);
    if (need_acptr == -1) {
        goto e3;
    }

    init_cstats(cfsp->rtpp_stats, &cmd_cf->cstats);

    if (pthread_mutex_init(&cmd_cf->cmd_mutex, NULL) != 0) {
        goto e4;
    }
    assert(cfsp->rtpp_timed_cf != NULL);
    cmd_cf->rcache = rtpp_cmd_rcache_ctor(cfsp->rtpp_timed_cf,
      32.0 + 3.0);
    if (cmd_cf->rcache == NULL) {
        goto e5;
    }

#if 0
    recfilter_init(&cmd_cf->average_load, 0.999, 0.0, 1);
#endif

    cmd_cf->cf_save = cfsp;
    if (need_acptr != 0) {
        if (pthread_create(&cmd_cf->acpt_thread_id, NULL,
          (void *(*)(void *))&rtpp_cmd_acceptor_run, cmd_cf) != 0) {
            goto e6;
        }
        cmd_cf->acceptor_started = 1;
#if HAVE_PTHREAD_SETNAME_NP
        (void)pthread_setname_np(cmd_cf->acpt_thread_id, "rtpp_cmd_acceptor");
#endif
    }
    if (pthread_create(&cmd_cf->thread_id, NULL,
      (void *(*)(void *))&rtpp_cmd_queue_run, cmd_cf) != 0) {
        goto e7;
    }
#if HAVE_PTHREAD_SETNAME_NP
    (void)pthread_setname_np(cmd_cf->thread_id, "rtpp_cmd_queue");
#endif
    cmd_cf->pub.dtor = &rtpp_command_async_dtor;
    cmd_cf->pub.wakeup = &rtpp_command_async_wakeup;
    cmd_cf->pub.get_aload = &rtpp_command_async_get_aload;
    cmd_cf->pub.reg_overload = &rtpp_command_async_reg_overload;
    cmd_cf->pub.chk_overload = &rtpp_command_async_chk_overload;
    return (&cmd_cf->pub);

e7:
    if (cmd_cf->acceptor_started != 0) {
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        cmd_cf->tstate_acceptor = TSTATE_CEASE;
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);
        for (i = 0; i < cmd_cf->aset.pfds_used; i ++) {
            close(cmd_cf->aset.pfds[i].fd);
        }
        pthread_join(cmd_cf->acpt_thread_id, NULL);
    }
e6:
    CALL_METHOD(cmd_cf->rcache, shutdown);
    RTPP_OBJ_DECREF(cmd_cf->rcache);
e5:
    pthread_mutex_destroy(&cmd_cf->cmd_mutex);
e4:
    free_accptset(&cmd_cf->aset);
e3:
    free_pollset(&cmd_cf->pset);
e2:
    for (int k = 0; k < 2; k++)
        close(cmd_cf->wakefds[k]);
e1:
    free(cmd_cf);
e0:
    return (NULL);
}

static void
rtpp_command_async_dtor(struct rtpp_cmd_async *pub)
{
    struct rtpp_cmd_async_cf *cmd_cf;
    int i;

    PUB2PVT(pub, cmd_cf);

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    cmd_cf->tstate_queue = TSTATE_CEASE;
    /* nudge acceptor thread */
    if (cmd_cf->acceptor_started != 0) {
        cmd_cf->tstate_acceptor = TSTATE_CEASE;
        for (i = 0; i < cmd_cf->aset.pfds_used; i ++) {
            close(cmd_cf->aset.pfds[i].fd);
        }
    }
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);
    /* notify worker thread */
    if (rtpp_command_async_wakeup(pub, 0) < 0)
        pthread_kill(cmd_cf->thread_id, SIGKILL);
    pthread_join(cmd_cf->thread_id, NULL);        
    if (cmd_cf->acceptor_started != 0) {
        pthread_join(cmd_cf->acpt_thread_id, NULL);
    }
    CALL_METHOD(cmd_cf->rcache, shutdown);
    RTPP_OBJ_DECREF(cmd_cf->rcache);
    pthread_mutex_destroy(&cmd_cf->cmd_mutex);
    free_pollset(&cmd_cf->pset);
    free_accptset(&cmd_cf->aset);
    for (int k = 0; k < 2; k++)
        close(cmd_cf->wakefds[k]);
    free(cmd_cf);
}
