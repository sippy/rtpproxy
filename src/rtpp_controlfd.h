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

enum rtpp_ctrl_type {RTPC_IFSUN, RTPC_UDP4, RTPC_UDP6, RTPC_SYSD, RTPC_STDIO,
  RTPC_FD, RTPC_IFSUN_C, RTPC_TCP4, RTPC_TCP6};

struct rtpp_ctrl_sock {
    struct rtpp_type_linkable t;
    enum rtpp_ctrl_type type;
    const char *cmd_sock;
    int controlfd_in;
    int controlfd_out;
    int port_ctl;                   /* Port number for UDP control, 0 for Unix domain */
    int exit_on_close;
    struct {				/* Temporary space for emergencies (i.e. ENOMEM) */
        char buf[RTPP_CMD_BUFLEN];	/* I/O scrap buffer */
        struct sockaddr_storage addr;	/* space to store receiver's address */
    } emrg;
    struct sockaddr_storage bindaddr;
};

#define RTPP_CTRL_ISDG(rcsp) ((rcsp)->type == RTPC_UDP4 || (rcsp)->type == RTPC_UDP6)
#define RTPP_CTRL_ISUNIX(rcsp) ((rcsp)->type == RTPC_IFSUN || (rcsp)->type == RTPC_IFSUN_C)
#define RTPP_CTRL_ISSTREAM(rcsp) ((rcsp)->type == RTPC_IFSUN_C || (rcsp)->type == RTPC_STDIO \
  || (rcsp)->type == RTPC_TCP4 || (rcsp)->type == RTPC_TCP6 || (rcsp)->type == RTPC_FD \
  || (rcsp)->type == RTPC_SYSD)
#define RTPP_CTRL_ACCEPTABLE(rcsp) ((rcsp)->type == RTPC_IFSUN || (rcsp)->type == RTPC_IFSUN_C \
  || (rcsp)->type == RTPC_TCP4 || (rcsp)->type == RTPC_TCP6 || (rcsp)->type == RTPC_SYSD)

int rtpp_controlfd_init(const struct rtpp_cfg *);
struct rtpp_ctrl_sock *rtpp_ctrl_sock_parse(const char *);
const char *rtpp_ctrl_sock_describe(struct rtpp_ctrl_sock *);
void rtpp_controlfd_cleanup(const struct rtpp_cfg *);
socklen_t rtpp_csock_addrlen(struct rtpp_ctrl_sock *);
