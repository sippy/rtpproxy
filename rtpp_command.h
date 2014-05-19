/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id$
 *
 */

#ifndef _RTPP_COMMAND_H_
#define _RTPP_COMMAND_H_

#define ECODE_CMDUNKN   0

#define ECODE_PARSE_1   1
#define ECODE_PARSE_2   2
#define ECODE_PARSE_3   3
#define ECODE_PARSE_4   4
#define ECODE_PARSE_5   5
#define ECODE_PARSE_6   6
#define ECODE_PARSE_7   7
#define ECODE_PARSE_8   8
#define ECODE_PARSE_9   9
#define ECODE_PARSE_10  10
#define ECODE_PARSE_11  11
#define ECODE_PARSE_12  12
#define ECODE_PARSE_13  13
#define ECODE_PARSE_14  14
#define ECODE_PARSE_15  15
#define ECODE_PARSE_16  16

#define ECODE_INVLARG_1 31
#define ECODE_INVLARG_2 32
#define ECODE_INVLARG_3 33
#define ECODE_INVLARG_4 34
#define ECODE_INVLARG_5 35

#define ECODE_SESUNKN   50

#define ECODE_PLRFAIL   60

#define ECODE_LSTFAIL_1 71
#define ECODE_LSTFAIL_2 72
#define ECODE_LSTFAIL_3 73

#define ECODE_NOMEM_1   81
#define ECODE_NOMEM_2   82
#define ECODE_NOMEM_3   83
#define ECODE_NOMEM_4   84
#define ECODE_NOMEM_5   85

#define ECODE_SLOWSHTDN 99

struct proto_cap {
    const char  *pc_id;
    const char  *pc_description;
};

struct rtpp_command;
struct cfg;
struct cfg_stable;

extern struct proto_cap proto_caps[];

int handle_command(struct cfg *, int, struct rtpp_command *, double);
void free_command(struct rtpp_command *);
struct rtpp_command *get_command(struct cfg *, int, int *);

#endif
