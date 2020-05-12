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

#include <stdlib.h>

#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_util.h"
#include "rtpp_modman.h"
#include "rtpp_command_args.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc.h"

int
rtpp_subcommand_ul_opts_parse(const struct rtpp_cfg *cfsp,
  const struct rtpp_command_args *subc_args, struct after_success_h *asp)
{
    int mod_id, inst_id;
    const char *cp;

    switch(subc_args->v[0][0]) {
    case 'M':
    case 'm':
        if (atoi_safe_sep(&subc_args->v[0][1], &mod_id, ':', &cp) != ATOI_OK)
            return (-1);
        if (atoi_safe(cp, &inst_id) != ATOI_OK)
            return (-1);
        if (mod_id < 1 || inst_id < 1)
            return (-1);
        if (CALL_METHOD(cfsp->modules_cf, get_ul_subc_h, (unsigned)mod_id,
          (unsigned)inst_id, asp) != 0)
            return (-1);
        break;

    default:
        return (-1);
    }
    return (0);
}
