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
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_defines.h"
#include "rtpp_list.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg.h"
#include "rtpp_command.h"
#include "rtpp_controlfd.h"
#include "rtpp_mallocs.h"
#include "rtpp_network.h"
#include "rtpp_runcreds.h"
#include "rtpp_util.h"

#if !defined(NO_ERR_H)
#include <err.h>
#endif

#ifdef HAVE_SYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif

static int
controlfd_init_systemd(void)
{
#ifdef HAVE_SYSTEMD_DAEMON
    int nfd;

    nfd = sd_listen_fds(0);
    if (nfd > 1) {
        warnx("Too many file descriptors received.");
        return (-1);
    }
    if (nfd == 1) {
        return (SD_LISTEN_FDS_START + 0);
    }
#else
    warnx("systemd is not supported or not detected on your system, "
      "please consider filing report or submitting a patch");
#endif
    return (-1);
}

static int
controlfd_init_ifsun(const struct rtpp_cfg *cfsp, struct rtpp_ctrl_sock *csp)
{
    int controlfd, reuse;
    struct sockaddr_un *ifsun;

    if (strlen(csp->cmd_sock) >= sizeof(ifsun->sun_path)) {
        warnx("socket name is too long: %s", csp->cmd_sock);
        errno = ENAMETOOLONG;
        return (-1);
    }
    unlink(csp->cmd_sock);
    ifsun = sstosun(&csp->bindaddr);
    memset(ifsun, '\0', sizeof(struct sockaddr_un));
#if defined(HAVE_SOCKADDR_SUN_LEN)
    ifsun->sun_len = strlen(csp->cmd_sock);
#endif
    ifsun->sun_family = AF_LOCAL;
    strlcpy(ifsun->sun_path, csp->cmd_sock, sizeof(ifsun->sun_path));
    controlfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (controlfd == -1) {
        warn("can't create socket");
        return (-1);
    }
    reuse = 1;
    setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(controlfd, sstosa(ifsun), sizeof(struct sockaddr_un)) < 0) {
        warn("can't bind to a socket: %s", csp->cmd_sock);
        goto e0;
    }
    if ((cfsp->runcreds->uname != NULL || cfsp->runcreds->gname != NULL) &&
      chown(csp->cmd_sock, cfsp->runcreds->uid, cfsp->runcreds->gid) == -1) {
        warn("can't set owner of the socket: %s", csp->cmd_sock);
        goto e0;
    }
    if ((cfsp->runcreds->gname != NULL) && cfsp->runcreds->sock_mode != 0 &&
      (chmod(csp->cmd_sock, cfsp->runcreds->sock_mode) == -1)) {
        warn("can't allow rw acces to group");
        goto e0;
    }
    if (listen(controlfd, 32) != 0) {
        warn("can't listen on a socket: %s", csp->cmd_sock);
        goto e0;
    }

    return (controlfd);
e0:
    close(controlfd);
    return (-1);
}

static int
controlfd_init_udp(const struct rtpp_cfg *cfsp, struct rtpp_ctrl_sock *csp)
{
    struct sockaddr *ifsin;
    char *cp, *tcp = NULL;
    int controlfd, so_rcvbuf, i, r;

    cp = strrchr(csp->cmd_sock, ':');
    if (cp != NULL) {
        *cp = '\0';
        tcp = cp;
        cp++;
    }
    if (cp == NULL || *cp == '\0')
        cp = CPORT;
    csp->port_ctl = atoi(cp);
    i = (csp->type == RTPC_UDP6) ? AF_INET6 : AF_INET;
    ifsin = sstosa(&csp->bindaddr);
    r = setbindhost(ifsin, i, csp->cmd_sock, cp, cfsp->no_resolve);
    if (tcp != NULL)
        *tcp = ':';
    if (r != 0) {
        warnx("setbindhost failed");
        return (-1);
    }
    controlfd = socket(i, SOCK_DGRAM, 0);
    if (controlfd == -1) {
        warn("can't create socket");
        return (-1);
    }
    so_rcvbuf = 16 * 1024;
    if (setsockopt(controlfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf)) == -1)
        RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "unable to set 16K receive buffer size on controlfd");
    if (bind(controlfd, ifsin, SA_LEN(ifsin)) < 0) {
        warn("can't bind to a socket: %s", csp->cmd_sock);
        close(controlfd);
        return (-1);
    }

    return (controlfd);
}

static int
controlfd_init_tcp(const struct rtpp_cfg *cfsp, struct rtpp_ctrl_sock *csp)
{
    struct sockaddr *ifsin;
    char *cp, *tcp = NULL;;
    int controlfd, so_rcvbuf, i, r;

    cp = strrchr(csp->cmd_sock, ':');
    if (cp != NULL) {
        *cp = '\0';
        tcp = cp;
        cp++;
    }
    if (cp == NULL || *cp == '\0')
        cp = CPORT;
    csp->port_ctl = atoi(cp);
    i = (csp->type == RTPC_TCP6) ? AF_INET6 : AF_INET;
    ifsin = sstosa(&csp->bindaddr);
    r = setbindhost(ifsin, i, csp->cmd_sock, cp, cfsp->no_resolve);
    if (tcp != NULL)
        *tcp = ':';
    if (r != 0) {
        warnx("setbindhost failed");
        return (-1);
    }
    controlfd = socket(i, SOCK_STREAM, 0);
    if (controlfd == -1) {
        warn("can't create socket");
        return (-1);
    }
    so_rcvbuf = 16 * 1024;
    if (setsockopt(controlfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf)) == -1)
        RTPP_ELOG(cfsp->glog, RTPP_LOG_ERR, "unable to set 16K receive buffer size on controlfd");
    if (bind(controlfd, ifsin, SA_LEN(ifsin)) < 0) {
        warn("can't bind to a socket: %s", csp->cmd_sock);
        goto e0;
    }
    if (listen(controlfd, 32) != 0) {
        warn("can't listen on a socket: %s", csp->cmd_sock);
        goto e0;
    }

    return (controlfd);
e0:
    close(controlfd);
    return (-1);
}

int
rtpp_controlfd_init(const struct rtpp_cfg *cfsp)
{
    int controlfd_in, controlfd_out, flags;
    struct rtpp_ctrl_sock *ctrl_sock;

    for (ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
      ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        switch (ctrl_sock->type) {
        case RTPC_SYSD:
            controlfd_in = controlfd_out = controlfd_init_systemd();
            break;

        case RTPC_IFSUN:
        case RTPC_IFSUN_C:
            controlfd_in = controlfd_out = controlfd_init_ifsun(cfsp, ctrl_sock);
            break;

        case RTPC_UDP4:
        case RTPC_UDP6:
            controlfd_in = controlfd_out = controlfd_init_udp(cfsp, ctrl_sock);
            break;

        case RTPC_TCP4:
        case RTPC_TCP6:
            controlfd_in = controlfd_out = controlfd_init_tcp(cfsp, ctrl_sock);
            break;

        case RTPC_STDIO:
            controlfd_in = fileno(stdin);
            controlfd_out = fileno(stdout);
            break;

        case RTPC_FD:
            if (atoi_safe(ctrl_sock->cmd_sock, &controlfd_in) != ATOI_OK ||
              controlfd_in < 0) {
                warnx("invalid fd: %s", ctrl_sock->cmd_sock);
                return (-1);
            }
            controlfd_out = controlfd_in;
            break;
        default:
            warnx("unhandled RTPC_XXX type: %d", ctrl_sock->type);
            abort();
        }
        if (controlfd_in < 0 || controlfd_out < 0) {
            return (-1);
        }
        ctrl_sock->controlfd_in = controlfd_in;
        ctrl_sock->controlfd_out = controlfd_out;
        flags = fcntl(controlfd_in, F_GETFL);
        if (flags < 0 || fcntl(controlfd_in, F_SETFL, flags | O_NONBLOCK) < 0) {
            warn("can't set O_NONBLOCK on a socket: %d", controlfd_in);
            return (-1);
        }
    }

    return (0);
}

socklen_t
rtpp_csock_addrlen(struct rtpp_ctrl_sock *ctrl_sock)
{

    switch (ctrl_sock->type) {
    case RTPC_IFSUN:
    case RTPC_IFSUN_C:
        return (sizeof(struct sockaddr_un));

    case RTPC_UDP4:
    case RTPC_TCP4:
        return (sizeof(struct sockaddr_in));

    case RTPC_UDP6:
    case RTPC_TCP6:
        return (sizeof(struct sockaddr_in6));
            
    case RTPC_SYSD:
        return (sizeof(struct sockaddr_un));
            
    default:
        break;
    }

    return (0);
}

void
rtpp_controlfd_cleanup(const struct rtpp_cfg *cfsp)
{
    struct rtpp_ctrl_sock *ctrl_sock;

    for (ctrl_sock = RTPP_LIST_HEAD(cfsp->ctrl_socks);
      ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {
        if (RTPP_CTRL_ISUNIX(ctrl_sock) == 0)
            continue;
        unlink(ctrl_sock->cmd_sock);
    }
}

struct rtpp_ctrl_sock *
rtpp_ctrl_sock_parse(const char *optarg)
{
    struct rtpp_ctrl_sock *rcsp;

    rcsp = rtpp_zmalloc(sizeof(struct rtpp_ctrl_sock));
    if (rcsp == NULL) {
        return (NULL);
    }
    rcsp->type= RTPC_IFSUN;
    if (strncmp("udp:", optarg, 4) == 0) {
        rcsp->type= RTPC_UDP4;
        optarg += 4;
    } else if (strncmp("udp6:", optarg, 5) == 0) {
        rcsp->type= RTPC_UDP6;
        optarg += 5;
    } else if (strncmp("unix:", optarg, 5) == 0) {
        rcsp->type= RTPC_IFSUN;
        optarg += 5;
    } else if (strncmp("cunix:", optarg, 6) == 0) {
        rcsp->type= RTPC_IFSUN_C;
        optarg += 6;
    } else if (strncmp("systemd:", optarg, 8) == 0) {
        rcsp->type= RTPC_SYSD;
        optarg += 8;
    } else if (strncmp("stdio:", optarg, 6) == 0) {
        rcsp->type= RTPC_STDIO;
        optarg += 6;
    } else if (strncmp("stdioc:", optarg, 7) == 0) {
        rcsp->type= RTPC_STDIO;
        rcsp->exit_on_close = 1;
        optarg += 7;
#if defined(LIBRTPPROXY)
    } else if (strncmp("fd:", optarg, 3) == 0) {
        rcsp->type= RTPC_FD;
        optarg += 3;
#endif
    } else if (strncmp("tcp:", optarg, 4) == 0) {
        rcsp->type= RTPC_TCP4;
        optarg += 4;
    } else if (strncmp("tcp6:", optarg, 5) == 0) {
        rcsp->type= RTPC_TCP6;
        optarg += 5;
    }
    rcsp->cmd_sock = optarg;

    return (rcsp);
}

#if 0
const char *
rtpp_ctrl_sock_describe(struct rtpp_ctrl_sock *rcsp)
{

    switch (rcsp->type) {
    case RTPC_IFSUN:
        return "unix";

    case RTPC_UDP4:
        return "udp";

    case RTPC_UDP6:
        return "udp6";

    case RTPC_IFSUN_C:
        return "cunix";

    case RTPC_SYSD:
        return "systemd";

    case RTPC_STDIO:
        return "stdio";

    case RTPC_TCP4:
        return "tcp";

    case RTPC_TCP6:
        return "tcp6";

    default:
        abort();
    }
}
#endif
