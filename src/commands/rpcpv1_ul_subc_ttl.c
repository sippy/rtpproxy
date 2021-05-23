/*
 * Copyright (c) 2021 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_stream.h"
#include "rtpp_ttl.h"
#include "rtpp_command_sub.h"
#include "commands/rpcpv1_ul.h"
#include "commands/rpcpv1_ul_subc_ttl.h"

int
rtpp_subcommand_ttl_handler(const struct after_success_h_args *ashap,
  const struct rtpp_subc_ctx *rscp)
{
    const struct rtpp_subcommand_ttl *tap;
    struct rtpp_stream *strmp;

    tap = (struct rtpp_subcommand_ttl *)ashap->dyn;
    switch (tap->direction) {
    case TTL_FORWARD:
        strmp = rscp->strmp_in;
        break;

    case TTL_REVERSE:
        strmp = rscp->strmp_out;
        if (strmp == NULL)
            return (-1);
        break;

    default:
        abort();
    }

    CALL_SMETHOD(strmp->ttl, reset_with, tap->ttl);
    return (0);
}
