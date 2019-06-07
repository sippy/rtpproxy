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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_defines.h"
#include "rtpp_list.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_command.h"
#include "rtpp_controlfd.h"
#include "rtpp_mallocs.h"
#include "rtpp_network.h"
#include "rtpp_runcreds.h"

#include "config_pp.h"

#if !defined(NO_ERR_H)
#include <err.h>
#endif

#ifdef HAVE_SYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif

/***********************************************************
    Check for file descriptors passed by the system manager.
    Returns SD_LISTEN_FDS_START on success
************************************************************/
static int
controlfd_init_systemd(void)
{
// if systemd is installed
#ifdef HAVE_SYSTEMD_DAEMON
    int nfd, controlfd;

    nfd = sd_listen_fds(0);                             // returns the number of received file descriptors
    if (nfd > 1) {
        warnx("Too many file descriptors received.");   // for cases when more than 1 fd received
        return (-1);
    }
    if (nfd == 1) {
        return (SD_LISTEN_FDS_START + 0);               // SD_LISTEN_FDS_START = 3
    }
// if systemd is NOT installed
#else
    warnx("systemd is not supported or not detected on your system, "
      "please consider filing report or submitting a patch");
#endif
    return (-1);
}

/*************************************************************
    open a unix domain socket descriptor and start listening
**************************************************************/
static int
controlfd_init_ifsun(struct cfg *cf, struct rtpp_ctrl_sock *csp)
{
    int controlfd, reuse;
    struct sockaddr_un *ifsun;

    unlink(csp->cmd_sock);                                  // delete control socket file
    ifsun = sstosun(&csp->bindaddr);                        // cast sockaddr_storage to sockaddr_un
    memset(ifsun, '\0', sizeof(struct sockaddr_un));        // null out the UNIX domain socket address
#if defined(HAVE_SOCKADDR_SUN_LEN)
    ifsun->sun_len = strlen(csp->cmd_sock);                 // set a length of sockaddr struct
#endif
    ifsun->sun_family = AF_LOCAL;                           // set addressing family to AF_LOCAL, AF_LOCAL - a socket family is used to communicate between processes on the same machine
    strcpy(ifsun->sun_path, csp->cmd_sock);                 // file name of cmd_socket
    controlfd = socket(AF_LOCAL, SOCK_STREAM, 0);           // open a UNIX stream-oriented socket
    if (controlfd == -1) {                                  // treat with an error message on a fail case
        warn("can't create socket");
        return (-1);
    }
    reuse = 1;// allow reuse of local addresses
    setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));                     // set an option to socket allowing reuse of local addresses
    if (bind(controlfd, sstosa(ifsun), sizeof(struct sockaddr_un)) < 0) {                       // assign the ifsun address to a socket, sstosa() - converts structure to sockaddr
        warn("can't bind to a socket: %s", csp->cmd_sock);                                      // treat a fail case
        goto e0;//close a socket immideatelly
    }
    if ((cf->stable->runcreds->uname != NULL || cf->stable->runcreds->gname != NULL) &&
      chown(csp->cmd_sock, cf->stable->runcreds->uid, cf->stable->runcreds->gid) == -1) {       // set user and group rights for a socket file
        warn("can't set owner of the socket: %s", csp->cmd_sock);                               // treat a fail case
        goto e0;//close a socket immideatelly
    }
    if ((cf->stable->runcreds->gname != NULL) && cf->stable->runcreds->sock_mode != 0 &&
      (chmod(csp->cmd_sock, cf->stable->runcreds->sock_mode) == -1)) {                          // set rights mode for a socket file
        warn("can't allow rw acces to group");                                                  // treat a fail case
        goto e0;//close a socket immideatelly
    }
    if (listen(controlfd, 32) != 0) {                                                           // start listening with a maximum pending connections set to 32
        warn("can't listen on a socket: %s", csp->cmd_sock);                                    // treat a fail case
        goto e0;//close a socket immideatelly
    }

    return (controlfd); // return a socket descriptor number
e0:
    close(controlfd);   // close a socket
    return (-1);
}

/*************************************************************
    open a datagram socket and bind a sockaddr address to it
**************************************************************/
static int
controlfd_init_udp(struct cfg *cf, struct rtpp_ctrl_sock *csp)
{
    struct sockaddr *ifsin;
    char *cp;
    int controlfd, so_rcvbuf, i;

    cp = strrchr(csp->cmd_sock, ':');                                       // pass the 'udp:' part of socket value
    if (cp != NULL) {
        *cp = '\0';
        cp++;
    }
    if (cp == NULL || *cp == '\0')                                          // if address was omitted, listen to 22222 on all interfaces
        cp = CPORT;
    csp->port_ctl = atoi(cp);                                               // set a controlling port to value defined above
    i = (csp->type == RTPC_UDP6) ? AF_INET6 : AF_INET;                      // if control socket type is UDP6 set address family to AF_INET6
    ifsin = sstosa(&csp->bindaddr);                                         // cast sockaddr_storage to sockaddr
    if (setbindhost(ifsin, i, csp->cmd_sock, cp) != 0) {                    // specify a bind host that the transform should use
        warnx("setbindhost failed");                                        // treat a fail case
        return (-1);
    }
    controlfd = socket(i, SOCK_DGRAM, 0);                                   // open a datagram socket
    if (controlfd == -1) {                                                  // treat a fail case
        warn("can't create socket");
        return (-1);
    }
    so_rcvbuf = 16 * 1024;  // define a receive buffer size
    if (setsockopt(controlfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf)) == -1)                  // set a receive buffer size to a socket
        RTPP_ELOG(cf->stable->glog, RTPP_LOG_ERR, "unable to set 16K receive buffer size on controlfd");    // treat a fail case
    if (bind(controlfd, ifsin, SA_LEN(ifsin)) < 0) {                                                        // assign the ifsin address to a socket
        warn("can't bind to a socket");                                                                     // treat a fail case
        close(controlfd);   // close controling socket
        return (-1);
    }

    return (controlfd); // return a file descriptor
}

/***************************************************************************
    open a two-way, reliable (TCP) socket and bind a sockaddr address to it, 
    then start of listening
****************************************************************************/
static int
controlfd_init_tcp(struct cfg *cf, struct rtpp_ctrl_sock *csp)
{
    struct sockaddr *ifsin;
    char *cp;
    int controlfd, so_rcvbuf, i;

    cp = strrchr(csp->cmd_sock, ':');                           // pass the 'tcp:' part of socket value
    if (cp != NULL) {
        *cp = '\0';
        cp++;
    }
    if (cp == NULL || *cp == '\0')                              // if address was omitted, listen to 22222 on all interfaces
        cp = CPORT;
    csp->port_ctl = atoi(cp);                                   // set a controlling port to value defined above
    i = (csp->type == RTPC_TCP6) ? AF_INET6 : AF_INET;          // if control socket type is TCP6 set address family to AF_INET6
    ifsin = sstosa(&csp->bindaddr);                             // cast sockaddr_storage to sockaddr
    if (setbindhost(ifsin, i, csp->cmd_sock, cp) != 0) {        // specify a bind host that the transform should use
        warnx("setbindhost failed");                            // treat a fail case
        return (-1);
    }
    controlfd = socket(i, SOCK_STREAM, 0);                      // open a reliable, two-way, stream oriented socket
    if (controlfd == -1) {
        warn("can't create socket");                            // treat a fail case
        return (-1);
    }
    so_rcvbuf = 16 * 1024;  // define a receive buffer size
    if (setsockopt(controlfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(so_rcvbuf)) == -1)                  // set a receive buffer size to a socket
        RTPP_ELOG(cf->stable->glog, RTPP_LOG_ERR, "unable to set 16K receive buffer size on controlfd");    // treat a fail case
    if (bind(controlfd, ifsin, SA_LEN(ifsin)) < 0) {                                                        // assign the ifsin address to a socket
        warn("can't bind to a socket");                                                                     // treat a fail case
        goto e0;//close a socket immideatelly
    }
    if (listen(controlfd, 32) != 0) {                           // start listening with a maximum pending connections set to 32
        warn("can't listen on a socket: %s", csp->cmd_sock);    // treat a fail case
        goto e0;//close a socket immideatelly
    }

    return (controlfd); // return a file descriptor number
e0:
    close(controlfd);   // close a socket
    return (-1);
}

/**************************************************************************************************
    Go through the list of control sockets defined by the user and start listening for connections
    for each of determined sockets.
    Set a standard input and output for a determined socket.
***************************************************************************************************/
int
rtpp_controlfd_init(struct cfg *cf)
{
    int controlfd_in, controlfd_out, flags;
    struct rtpp_ctrl_sock *ctrl_sock;

    // iterate through the list of defined control sockets
    // set a standard input and output for a determined socket
    // start with a head of the sockets list
    for (ctrl_sock = RTPP_LIST_HEAD(cf->stable->ctrl_socks);
      ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {                   // itirate through each one until you get the end of the list
        switch (ctrl_sock->type) {                                                  // determine a control socket type
        case RTPC_SYSD:
            controlfd_in = controlfd_out = controlfd_init_systemd();                // check for file descriptors passed by the system manager
            break;

        case RTPC_IFSUN:
        case RTPC_IFSUN_C:
            controlfd_in = controlfd_out = controlfd_init_ifsun(cf, ctrl_sock);     // open a unix domain socket and start listening
            break;

        case RTPC_UDP4:
        case RTPC_UDP6:
            controlfd_in = controlfd_out = controlfd_init_udp(cf, ctrl_sock);       // open a datagram socket (UDP)
            break;

        case RTPC_TCP4:
        case RTPC_TCP6:
            controlfd_in = controlfd_out = controlfd_init_tcp(cf, ctrl_sock);       // open a stream socket and start listening (TCP)
            break;

        case RTPC_STDIO:                                    // case with a standard intput output
            controlfd_in = fileno(stdin);                   // file descriptor number associated with a standard input
            controlfd_out = fileno(stdout);                 // file descriptor number associated with a standard output
            break;
        }
        if (controlfd_in < 0 || controlfd_out < 0) {        // if no socket control input or output defined
            return (-1);
        }
        flags = fcntl(controlfd_in, F_GETFL);               // get a file status flag
        fcntl(controlfd_in, F_SETFL, flags | O_NONBLOCK);   // update file flags with a O_NONBLOCK to prevent open blocking for a long time
        ctrl_sock->controlfd_in = controlfd_in;             // update a ctrl_sock structure with a control input descriptor number
        ctrl_sock->controlfd_out = controlfd_out;           // update a ctrl_sock structure with a control output descriptor number
    }

    return (0); // if everything went okay
}

/**********************************************************************
    Get socket addr length, depenends on a kind of socket passed
**********************************************************************/
int
rtpp_csock_addrlen(struct rtpp_ctrl_sock *ctrl_sock)
{

    switch (ctrl_sock->type) {              // determine a type of socket
    case RTPC_IFSUN:
    case RTPC_IFSUN_C:
        return (sizeof(struct sockaddr_un));

    case RTPC_UDP4:
    case RTPC_TCP4:
        return (sizeof(struct sockaddr_in));

    case RTPC_UDP6:
    case RTPC_TCP6:
        return (sizeof(struct sockaddr_in6));

    default:
        break;
    }

    return (-1);                            // treat a fail case
}

/**********************************************************************
    Delete all controlling unix sockets existing now
**********************************************************************/
void
rtpp_controlfd_cleanup(struct cfg *cf)
{
    struct rtpp_ctrl_sock *ctrl_sock;

    for (ctrl_sock = RTPP_LIST_HEAD(cf->stable->ctrl_socks);
      ctrl_sock != NULL; ctrl_sock = RTPP_ITER_NEXT(ctrl_sock)) {       // start with a head of the list and itirate through all existing sockets
        if (RTPP_CTRL_ISUNIX(ctrl_sock) == 0)                           // if it is not a unix socket just continue cycling through
            continue;
        unlink(ctrl_sock->cmd_sock);                                    // otherwise delete found unix controlling socket file
    }
}

/*********************************************************************************
    Function that parses which kind of a control socket user defined at start time

    optarg - is a parameter passed with '-s' option
            means it's a socket: UNIX control socket or UDP/TCP control socket
**********************************************************************************/
struct rtpp_ctrl_sock *
rtpp_ctrl_sock_parse(const char *optarg)
{
    struct rtpp_ctrl_sock *rcsp;

    rcsp = rtpp_zmalloc(sizeof(struct rtpp_ctrl_sock));         // allocation of memory for rtpp_ctrl_sock structure
    if (rcsp == NULL) {
        return (NULL);                                          // treat a failed allocation of memory
    }
    rcsp->type= RTPC_IFSUN;
    if (strncmp("udp:", optarg, 4) == 0) {                      // udp socket
        rcsp->type= RTPC_UDP4;                                  // set type to 1
        optarg += 4;//move to the value of a socket
    } else if (strncmp("udp6:", optarg, 5) == 0) {              // udp socket working over ipv6
        rcsp->type= RTPC_UDP6;                                  // set type to 2
        optarg += 5;//move to the value of a socket
    } else if (strncmp("unix:", optarg, 5) == 0) {              // unix socket
        rcsp->type= RTPC_IFSUN;                                 // set type to 0
        optarg += 5;//move to the value of a socket
    } else if (strncmp("cunix:", optarg, 6) == 0) {             // cunix socket
        rcsp->type= RTPC_IFSUN_C;                               // set type to 5
        optarg += 6;//move to the value of a socket
    } else if (strncmp("systemd:", optarg, 8) == 0) {           // systemd control socket
        rcsp->type= RTPC_SYSD;                                  // set type to 3
        optarg += 8;//move to the value of a socket
    } else if (strncmp("stdio:", optarg, 6) == 0) {
        rcsp->type= RTPC_STDIO;                                 // set type to 4
        optarg += 6;//move to the value of a socket
    } else if (strncmp("stdioc:", optarg, 7) == 0) {
        rcsp->type= RTPC_STDIO;                                 // set type to 4
        rcsp->exit_on_close = 1;
        optarg += 7;//move to the value of a socket
    } else if (strncmp("tcp:", optarg, 4) == 0) {               // tcp socket
        rcsp->type= RTPC_TCP4;                                  // set type to 6
        optarg += 4;//move to the value of a socket
    } else if (strncmp("tcp6:", optarg, 5) == 0) {              // tcp socket working over ipv6
        rcsp->type= RTPC_TCP6;                                  // set type to 7
        optarg += 5;//move to the value of a socket
    }
    rcsp->cmd_sock = optarg;    // set a cmd_sock value in the rcsp structure
                                // pointing to the value that user passed
    return (rcsp);              // return a pointer to rtpp_ctrl_sock structure
}

/* THIS PART REMOVED FROM A COMPILATION */
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
