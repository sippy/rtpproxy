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
#include <unistd.h>
#include <sys/un.h>

#include "rtpp_defines.h"
#include "rtpp_command.h"
#include "rtpp_network.h"
#include "rtpp_util.h"

static pthread_t rtpp_cmd_queue;

static void
process_commands(struct cfg *cf, int controlfd_in, double dtime)
{
    int controlfd, i;
    socklen_t rlen;
    struct sockaddr_un ifsun;
    struct rtpp_command cmd;

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
        if (get_command(&cf->stable, controlfd, &cmd) > 0) {
            pthread_mutex_lock(&cf->glock);
            i = handle_command(cf, controlfd, &cmd, dtime);
            pthread_mutex_unlock(&cf->glock);
        } else {
            i = -1;
        }
        if (cf->stable.umode == 0) {
            close(controlfd);
        }
    } while (i == 0);
}

static void
rtpp_cmd_queue_run(void *arg)
{
    struct cfg *cf;
    struct pollfd pfds[1];
    int i;
    double eptime;

    cf = (struct cfg *)arg;

    pfds[0].fd = cf->stable.controlfd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;

    for (;;) {
        i = poll(pfds, 1, INFTIM);
        if (i < 0 && errno == EINTR)
            continue;
        eptime = getdtime();
        if (i > 0 && (pfds[0].revents & POLLIN) != 0) {
            process_commands(cf, pfds[0].fd, eptime);
        }
    }
}

int
rtpp_command_async_init(struct cfg *cf)
{

    if (pthread_create(&rtpp_cmd_queue, NULL, (void *(*)(void *))&rtpp_cmd_queue_run, cf) != 0)
        return -1;

    return 0;
}
