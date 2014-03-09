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

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>

#include "rtpp_defines.h"
#include "rtpp_command.h"
#include "rtpp_command_async.h"
#include "rtpp_network.h"
#include "rtpp_util.h"

struct rtpp_cmd_async_cf {
    pthread_t thread_id;
    pthread_cond_t cmd_cond;
    pthread_mutex_t cmd_mutex;
    int clock_tick;
};

static void
process_commands(struct cfg *cf, int controlfd_in, double dtime)
{
    int controlfd, i, rval;
    socklen_t rlen;
    struct sockaddr_un ifsun;
    struct rtpp_command *cmd;

    do {
        if (cf->stable.umode == 0) {
            rlen = sizeof(ifsun);
            controlfd = accept(controlfd_in, sstosa(&ifsun), &rlen);
            if (controlfd == -1) {
                if (errno != EWOULDBLOCK)
                    rtpp_log_ewrite(RTPP_LOG_ERR, cf->stable.glog,
                      "can't accept connection on control socket");
                break;
            }
        } else {
            controlfd = controlfd_in;
        }
        cmd = get_command(&cf->stable, controlfd, &rval);
        if (cmd != NULL) {
            pthread_mutex_lock(&cf->glock);
            i = handle_command(cf, controlfd, cmd, dtime);
            pthread_mutex_unlock(&cf->glock);
            free_command(cmd);
        } else {
            i = -1;
        }
        if (cf->stable.umode == 0) {
            close(controlfd);
        }
    } while (i == 0 || cf->stable.umode == 0);
}

static void
rtpp_cmd_queue_run(void *arg)
{
    struct cfg *cf;
    struct rtpp_cmd_async_cf *cmd_cf;
    struct pollfd pfds[1];
    int i, last_ctick;
    double eptime;

    cf = (struct cfg *)arg;
    cmd_cf = cf->rtpp_cmd_cf;

    pfds[0].fd = cf->stable.controlfd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;

    pthread_mutex_lock(&cmd_cf->cmd_mutex);
    last_ctick = cmd_cf->clock_tick;
    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    for (;;) {
        pthread_mutex_lock(&cmd_cf->cmd_mutex);
        while (cmd_cf->clock_tick == last_ctick) {
            pthread_cond_wait(&cmd_cf->cmd_cond, &cmd_cf->cmd_mutex);
        }
        last_ctick = cmd_cf->clock_tick;
        pthread_mutex_unlock(&cmd_cf->cmd_mutex);

        i = poll(pfds, 1, 0);
        if (i < 0 && errno == EINTR)
            continue;
        if (i > 0 && (pfds[0].revents & POLLIN) != 0) {
            eptime = getdtime();
            process_commands(cf, pfds[0].fd, eptime);
        }
    }
}

int
rtpp_command_async_wakeup(struct rtpp_cmd_async_cf *cmd_cf, int clock)
{
    int old_clock;

    pthread_mutex_lock(&cmd_cf->cmd_mutex);

    old_clock = cmd_cf->clock_tick;
    cmd_cf->clock_tick = clock;

    /* notify worker thread */
    pthread_cond_signal(&cmd_cf->cmd_cond);

    pthread_mutex_unlock(&cmd_cf->cmd_mutex);

    return (old_clock);
}

int
rtpp_command_async_init(struct cfg *cf)
{
    struct rtpp_cmd_async_cf *cmd_cf;

    cmd_cf = malloc(sizeof(*cmd_cf));
    if (cmd_cf == NULL)
        return (-1);

    memset(cmd_cf, '\0', sizeof(*cmd_cf));

    pthread_cond_init(&cmd_cf->cmd_cond, NULL);
    pthread_mutex_init(&cmd_cf->cmd_mutex, NULL);

    cf->rtpp_cmd_cf = cmd_cf;
    if (pthread_create(&cmd_cf->thread_id, NULL, (void *(*)(void *))&rtpp_cmd_queue_run, cf) != 0) {
        pthread_cond_destroy(&cmd_cf->cmd_cond);
        pthread_mutex_destroy(&cmd_cf->cmd_mutex);
        free(cmd_cf);
        cf->rtpp_cmd_cf = NULL;
        return (-1);
    }

    return (0);
}
