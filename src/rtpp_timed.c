/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/stat.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_defines.h"
#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_types.h"
#include "rtpp_queue.h"
#include "rtpp_wi.h"
#include "rtpp_util.h"
#include "rtpp_timed.h"

struct rtpp_timed_cf {
    struct rtpp_queue *q;
    double last_run;
    double period;
};

struct rtpp_timed_wi {
    rtpp_timed_cb_t cb_func;
    void *cb_func_arg;
    double when;
};

int
rtpp_timed_init(struct cfg *cf)
{
    struct rtpp_timed_cf *rtcp;

    rtcp = malloc(sizeof(struct rtpp_timed_cf));
    if (rtcp == NULL) {
        return (-1);
    }
    memset(rtcp, '\0', sizeof(struct rtpp_timed_cf));
    rtcp->q = rtpp_queue_init(1, "rtpp_timed(requests)");
    if (rtcp->q == NULL) {
        free(rtcp);
        return (-1);
    }
    rtcp->last_run = getdtime();
    rtcp->period = 0.1;
    cf->stable->rtpp_timed_cf = rtcp;
    return (0);
}

void
rtpp_timed_destroy(struct cfg *cf)
{
    struct rtpp_wi *wi;
    struct rtpp_timed_wi *wi_data;
    double ctime;

    ctime = getdtime();
    while (rtpp_queue_get_length(cf->stable->rtpp_timed_cf->q) > 0) {
        wi = rtpp_queue_get_item(cf->stable->rtpp_timed_cf->q, 1);
        wi_data = rtpp_wi_data_get_ptr(wi, sizeof(struct rtpp_timed_wi));
        wi_data->cb_func(ctime, wi_data->cb_func_arg);
        rtpp_wi_free(wi);
    }

    rtpp_queue_destroy(cf->stable->rtpp_timed_cf->q);
    free(cf->stable->rtpp_timed_cf);
}


int
rtpp_timed_schedule(struct cfg *cf, double offset, rtpp_timed_cb_t cb_func,
  void *cb_func_arg)
{
    struct rtpp_wi *wi;
    struct rtpp_timed_wi wi_data;

    wi_data.cb_func = cb_func;
    wi_data.cb_func_arg = cb_func_arg;
    wi_data.when = getdtime() + offset;
    
    wi = rtpp_wi_malloc_data(&wi_data, sizeof(wi_data));
    if (wi == NULL) {
        return (-1);
    }
    rtpp_queue_put_item(wi, cf->stable->rtpp_timed_cf->q);
    return (0);
}

static int
rtpp_timed_istime(struct rtpp_wi *wi, void *ctimep)
{
    struct rtpp_timed_wi *wi_data;

    wi_data = rtpp_wi_data_get_ptr(wi, sizeof(struct rtpp_timed_wi));
    if (wi_data->when <= *(double *)ctimep)
       return (0);
    return (1);
}

void
rtpp_timed_process(struct cfg *cf, double ctime)
{
    struct rtpp_wi *wi;
    struct rtpp_timed_wi *wi_data;
    struct rtpp_timed_cf *rtcp;

    rtcp = cf->stable->rtpp_timed_cf;
    if (rtcp->last_run + rtcp->period > ctime)
        return;

    for (;;) {
        wi = rtpp_queue_get_first_matching(rtcp->q, rtpp_timed_istime, &ctime);
        if (wi == NULL) {
            return;
        }
        wi_data = rtpp_wi_data_get_ptr(wi, sizeof(struct rtpp_timed_wi));
        wi_data->cb_func(ctime, wi_data->cb_func_arg);
        rtpp_wi_free(wi);
    }
    rtcp->last_run = ctime;
}
