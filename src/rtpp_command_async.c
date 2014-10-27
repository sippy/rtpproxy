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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_defines.h"
#include "rtpp_command.h"
#include "rtpp_command_async.h"
#include "rtpp_command_private.h"
#include "rtpp_math.h"
#include "rtpp_network.h"
#include "rtpp_netio_async.h"
#include "rtpp_util.h"
#include "rtpp_types.h"
#include "rtpp_stats.h"

struct rtpp_cmd_pollset {
    struct pollfd *pfds;
    int pfds_used;
    int accept_fd;
    pthread_mutex_t pfds_mutex;
};

struct rtpp_cmd_async_cf {
    pthread_t thread_id;
    pthread_t acpt_thread_id;
    pthread_cond_t cmd_cond;
    pthread_mutex_t cmd_mutex;
    int clock_tick;
    double tused;
#if 0
    struct recfilter average_load;
#endif
    struct rtpp_command_stats cstats;
    struct rtpp_cmd_pollset pset;
};

static void
init_cstats(struct rtpp_stats_obj *sobj, struct rtpp_command_stats *csp)
{

    csp->ncmds_rcvd.cnt_idx = CALL_METHOD(sobj, getidxbyname, "ncmds_rcvd");
    csp->ncmds_succd.cnt_idx = CALL_METHOD(sobj, getidxbyname, "ncmds_succd");
    csp->ncmds_errs.cnt_idx = CALL_METHOD(sobj, getidxbyname, "ncmds_errs");
    csp->ncmds_repld.cnt_idx = CALL_METHOD(sobj, getidxbyname, "ncmds_repld");
}

#define FLUSH_CSTAT(sobj, st)    { \
    if ((st).cnt > 0) { \
        CALL_METHOD(sobj, updatebyidx, (st).cnt_idx, (st).cnt); \
        (st).cnt = 0; \
    } \
}

static void
flush_cstats(struct rtpp_stats_obj *sobj, struct rtpp_command_stats *csp)
{

    FLUSH_CSTAT(sobj, csp->ncmds_rcvd);
    FLUSH_CSTAT(sobj, csp->ncmds_succd);
    FLUSH_CSTAT(sobj, csp->ncmds_errs);
    FLUSH_CSTAT(sobj, csp->ncmds_repld);
}

static int
accept_connection(struct cfg *cf, int controlfd_in)
{
    int controlfd;
    socklen_t rlen;
    struct sockaddr_un ifsun;

    rlen = sizeof(ifsun);
    controlfd = accept(controlfd_in, sstosa(&ifsun), &rlen);
    if (controlfd == -1) {
        if (errno != EWOULDBLOCK) {
            rtpp_log_ewrite(RTPP_LOG_ERR, cf->stable->glog,
              "can't accept connection on control socket");
        }
        return (-1);
    }
    return (controlfd);
}

static int
process_commands(struct cfg *cf, int controlfd, double dtime,
  struct rtpp_command_stats *csp)
{
    int i, rval;
    struct rtpp_command *cmd;

    do {
        cmd = get_command(cf, controlfd, &rval, dtime, csp);
        if (cmd != NULL) {
            csp->ncmds_rcvd.cnt++;
            pthread_mutex_lock(&cf->glock);
            i = handle_command(cf, cmd);
            pthread_mutex_unlock(&cf->glock);
            free_command(cmd);
        } else {
            i = -1;
        }
    } while (i == 0 && cf->stable->umode != 0);
    return (i);
}

static void
rtpp_cmd_acceptor_run(void *arg)
{
    struct cfg *cf;
    struct rtpp_cmd_async_cf *cmd_cf;
    struct pollfd pfds[1], *tp;
    struct rtpp_cmd_pollset *psp;
    int nready, controlfd;

    cf = (struct cfg *)arg;
    cmd_cf = cf->stable->rtpp_cmd_cf;
    psp = &cmd_cf->pset;

    pfds[0].fd = psp->accept_fd;
    psp->pfds[0].events = POLLIN;
    psp->pfds[0].revents = 0;

    for (;;) {
        nready = poll(pfds, 1, INFTIM);
        if (nready <= 0)
            continue;
        if ((pfds[0].revents & POLLIN) == 0) {
            continue;
        }
        controlfd = accept_connection(cf, psp->accept_fd);
        if (controlfd < 0) {
            continue;
        }
        pthread_mutex_lock(&psp->pfds_mutex);
        tp = realloc(psp->pfds, sizeof(struct pollfd) * (psp->pfds_used + 1));
        if (tp == NULL) {
            pthread_mutex_unlock(&psp->pfds_mutex);
            continue;
        }
        psp->pfds = tp;
        psp->pfds[psp->pfds_used].fd = controlfd;
        psp->pfds[psp->pfds_used].events = POLLIN | POLLERR | POLLHUP;
        psp->pfds[psp->pfds_used].revents = 0;
        psp->pfds_used++;
        pthread_mutex_unlock(&psp->pfds_mutex);
        rtpp_command_async_wakeup(cmd_cf);
    }
}

static void
rtpp_cmd_queue_run(void *arg)
{
    struct cfg *cf;
    struct rtpp_cmd_async_cf *cmd_cf;
    struct rtpp_cmd_pollset *psp;
    int i, last_ctick, nready, rval;
    double sptime;
#if 0
    double eptime, tused;
#endif
    struct rtpp_command_stats *csp;
    struct rtpp_stats_obj *rtpp_stats_cf;

    cf = (struct cfg *)arg;
    cmd_cf = cf->stable->rtpp_cmd_cf;
    rtpp_stats_cf = cf->stable->rtpp_stats;
    csp = &cmd_cf->cstats;

    psp = &cmd_cf->pset;

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    last_ctick = cmd_cf->clock_tick;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    for (;;) {
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        while (cmd_cf->clock_tick == last_ctick) {
            pthread_cond_wait(&cmd_cf->cmd_cond, &cmd_cf->cmd_mutex);
        }
        last_ctick = cmd_cf->clock_tick;
#if 0
        tused = cmd_cf->tused;
#endif
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);

        sptime = getdtime();

        pthread_mutex_lock(&psp->pfds_mutex);
        if (psp->pfds_used == 0) {
            pthread_mutex_unlock(&psp->pfds_mutex);
            continue;
        }
        nready = poll(psp->pfds, psp->pfds_used, 0);
        if (nready < 0 && errno == EINTR) {
            pthread_mutex_unlock(&psp->pfds_mutex);
            continue;
        }
        if (nready > 0) {
            for (i = 0; i < psp->pfds_used; i++) {
                if (cf->stable->umode == 0 && (psp->pfds[i].revents & (POLLERR | POLLHUP)) != 0) {
                    goto closefd;
                }
                if ((psp->pfds[i].revents & POLLIN) == 0) {
                    continue;
                }
                rval = process_commands(cf, psp->pfds[i].fd, sptime, csp);
                if (cf->stable->umode == 0 && rval == -1) {
closefd:
                    close(psp->pfds[i].fd);
                    psp->pfds_used--;
                    if (psp->pfds_used > 0) {
                        if (i < psp->pfds_used) {
                            memcpy(&psp->pfds[i], &psp->pfds[i + 1],
                              (psp->pfds_used - i) * sizeof(struct pollfd));
                        }
                        psp->pfds = realloc(psp->pfds,
                          sizeof(struct pollfd) * psp->pfds_used);
                    }
                }
            }
        }
        pthread_mutex_unlock(&psp->pfds_mutex);
        if (nready > 0) {
            rtpp_anetio_pump(cf->stable->rtpp_netio_cf);
        }
#if 0
        eptime = getdtime();
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        recfilter_apply(&cmd_cf->average_load, (eptime - sptime + tused) * cf->stable->target_pfreq);
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);
#endif
        flush_cstats(rtpp_stats_cf, csp);
#if 0
#if RTPP_DEBUG
        if (last_ctick % (unsigned int)cf->stable->target_pfreq == 0 || last_ctick < 1000) {
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable->glog, "rtpp_cmd_queue_run %lld sptime %f eptime %f, CSV: %f,%f,%f,%f,%f", \
              last_ctick, sptime, eptime, (double)last_ctick / cf->stable->target_pfreq, \
              eptime - sptime + tused, eptime, sptime, tused);
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable->glog, "run %lld average load %f, CSV: %f,%f", last_ctick, \
              cmd_cf->average_load.lastval * 100.0, (double)last_ctick / cf->stable->target_pfreq, cmd_cf->average_load.lastval);
        }
#endif
#endif
    }
}

double
rtpp_command_async_get_aload(struct rtpp_cmd_async_cf *cmd_cf)
{
#if 0
    double aload;

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    aload = cmd_cf->average_load.lastval;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    return (aload);
#else
    return (0);
#endif
}

int
rtpp_command_async_wakeup(struct rtpp_cmd_async_cf *cmd_cf)
{
    int old_clock;

    pthread_mutex_lock(&cmd_cf->cmd_mutex);

    old_clock = cmd_cf->clock_tick;
    cmd_cf->clock_tick++;

    /* notify worker thread */
    pthread_cond_signal(&cmd_cf->cmd_cond);

    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    return (old_clock);
}

static int
init_pollset(struct cfg *cf, struct rtpp_cmd_pollset *psp, int controlfd)
{

    psp->pfds = malloc(sizeof(struct pollfd));
    if (psp->pfds == NULL) {
        return (-1);
    }
    if (pthread_mutex_init(&psp->pfds_mutex, NULL) != 0) {
        free(psp->pfds);
        return (-1);
    }
    psp->pfds_used = 1;
    if (cf->stable->umode == 0) {
        psp->pfds_used = 0;
        psp->accept_fd = controlfd;
    } else {
        psp->pfds_used = 1;
        psp->accept_fd = -1;
        psp->pfds[0].fd = controlfd;
        psp->pfds[0].events = POLLIN;
        psp->pfds[0].revents = 0;
    }
    return (0);
}

int
rtpp_command_async_init(struct cfg *cf)
{
    struct rtpp_cmd_async_cf *cmd_cf;

    cmd_cf = malloc(sizeof(*cmd_cf));
    if (cmd_cf == NULL)
        return (-1);

    memset(cmd_cf, '\0', sizeof(*cmd_cf));

    if (init_pollset(cf, &cmd_cf->pset, cf->stable->controlfd) == -1) {
        free(cmd_cf);
        return (-1);
    }

    init_cstats(cf->stable->rtpp_stats, &cmd_cf->cstats);

    pthread_cond_init(&cmd_cf->cmd_cond, NULL);
    pthread_mutex_init(&cmd_cf->cmd_mutex, NULL);

#if 0
    recfilter_init(&cmd_cf->average_load, 0.999, 0.0, 1);
#endif

    cf->stable->rtpp_cmd_cf = cmd_cf;
    if (cf->stable->umode == 0) {
        pthread_create(&cmd_cf->acpt_thread_id, NULL,
          (void *(*)(void *))&rtpp_cmd_acceptor_run, cf);
    }
    if (pthread_create(&cmd_cf->thread_id, NULL,
      (void *(*)(void *))&rtpp_cmd_queue_run, cf) != 0) {
        pthread_cond_destroy(&cmd_cf->cmd_cond);
        pthread_mutex_destroy(&cmd_cf->cmd_mutex);
        free(cmd_cf);
        cf->stable->rtpp_cmd_cf = NULL;
        return (-1);
    }

    return (0);
}
