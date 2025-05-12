/*
 * Copyright (c) 2006-2025 Sippy Software, Inc., http://www.sippysoft.com
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

#include <unistd.h>

#include "librtpproxy.h"
#include "librtpp_main.h"

struct opt_save {
    char *optarg;
    int optind;
    int optopt;
    int opterr;
    int optreset;
};

#if defined(__linux__)
static int optreset; /* Not present in linux */
#endif

#define OPT_SAVE(sp) (*(sp) = (struct opt_save){optarg, optind, optopt, opterr, optreset})
#define OPT_RESTORE(sp) ({ \
    optarg = (sp)->optarg; \
    optind = (sp)->optind; \
    optopt = (sp)->optopt; \
    opterr = (sp)->opterr; \
    optreset = (sp)->optreset; \
})

struct rtpp_cfg *
rtpp_main(int argc, const char * const *argv)
{
    struct rtpp_cfg *r;
    const struct opt_save opt_zero = {.optind = 1};
    struct opt_save opt_saved;

    OPT_SAVE(&opt_saved);
    OPT_RESTORE(&opt_zero);
    r = _rtpp_main(argc, argv);
    OPT_RESTORE(&opt_saved);
    return r;
}
