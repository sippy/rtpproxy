/*
 * Copyright (c) 2006-2020 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_util.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_modman.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc.h"
#include "commands/rpcpv1_delete.h"

#if ENABLE_MODULE_IF
static int
handle_mod_subc_parse(const struct rtpp_cfg *cfsp, const char *ip,
  struct after_success_h *asp)
{
    int mod_id, inst_id;
    const char *cp;

    if (atoi_safe_sep(ip, &mod_id, ':', &cp) != ATOI_OK)
        return (-1);
    if (atoi_safe(cp, &inst_id) != ATOI_OK)
        return (-1);
    if (mod_id < 1 || inst_id < 1)
        return (-1);
    if (CALL_METHOD(cfsp->modules_cf, get_ul_subc_h, (unsigned)mod_id,
        (unsigned)inst_id, asp) != 0)
        return (-1);
    return (0);
}
#endif

int
rtpp_subcommand_ul_opts_parse(const struct rtpp_cfg *cfsp, struct rtpp_command *cmd,
  const struct rtpp_command_args *subc_args, struct after_success_h *asp)
{
    struct delete_opts *dop;

    switch(subc_args->v[0].s[0]) {
    case 'M':
    case 'm':
#if ENABLE_MODULE_IF
        return (handle_mod_subc_parse(cfsp, &subc_args->v[0].s[1], asp));
#else
        RTPP_LOG(cfsp->glog, RTPP_LOG_WARN, "module command, but modules are not " \
          "compiled in: %s", subc_args->v[0].s);
        return (-1);
#endif
        break;

    case 'D':
    case 'd':
        if (subc_args->c != 1)
            return (-1);
        dop = rtpp_command_del_opts_parse(NULL, subc_args);
        if (dop == NULL)
            return (-1);
        asp->args.dyn = dop;
        RTPP_OBJ_DTOR_ATTACH_OBJ(cmd, dop);
        asp->args.stat = (void *)cfsp;
        asp->handler = handle_delete_as_subc;
        break;

    default:
        return (-1);
    }
    return (0);
}
