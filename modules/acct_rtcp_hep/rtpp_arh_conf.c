/*
 * Copyright (c) 2018 Sippy Software, Inc., http://www.sippysoft.com
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
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "config.h"

#include "rtpp_types.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_module.h"
#include "rtpp_ucl.h"

#include "ucl.h"

#include "hepconnector.h"

struct hep_ctx;

static const struct addrinfo udp_hints = { .ai_socktype = SOCK_DGRAM };
static const struct addrinfo tcp_hints = { .ai_socktype = SOCK_STREAM };

static bool
conf_set_capt_host(struct rtpp_log *log, const ucl_object_t *top,
  const ucl_object_t *obj, struct hep_ctx *target)
{
    const char *val = NULL;

    val = ucl_object_tostring_forced(obj);
    target->capt_host = mod_strdup(val);
    if (target->capt_host == NULL)
        return (false);

    return (true);
}

static bool
conf_set_capt_port(struct rtpp_log *log, const ucl_object_t *top,
  const ucl_object_t *obj, struct hep_ctx *target)
{

    const char *val = NULL;
    int rport;

    if (ucl_object_type(obj) == UCL_INT) {
        rport = ucl_object_toint(obj);
    } else {
        val = ucl_object_tostring_forced(obj);
        RTPP_LOG(log, RTPP_LOG_ERR, "error in config file; invalid value for port in section '%s': '%s'",
            ucl_object_key(obj), val);
	return (false);
    }
    if (rport <= 0 || rport > 0xffff) {
        RTPP_LOG(log, RTPP_LOG_ERR, "error in config file; invalid value for port in section '%s': %d",
            ucl_object_key(obj), rport);
        return (false);
    }
    snprintf(target->capt_port, sizeof(target->capt_port), "%d", rport);
    return (true);
}

static bool
conf_set_capt_ptype(struct rtpp_log *log, const ucl_object_t *top,
  const ucl_object_t *obj, struct hep_ctx *target)
{

    const char *val = NULL;

    val = ucl_object_tostring_forced(obj);
    if (strcasecmp(val, "udp") == 0) {
        target->hints = &udp_hints;
        return (true);
    } else if (strcasecmp(val, "tcp") == 0) {
        target->hints = &tcp_hints;
        return (true);
    }

    RTPP_LOG(log, RTPP_LOG_ERR, "error in config file; invalid value for ptype in section '%s': '%s'",
      ucl_object_key(obj), val);
    return (false);
}

static bool
conf_set_capt_id(struct rtpp_log *log, const ucl_object_t *top,
  const ucl_object_t *obj, struct hep_ctx *target)
{

    const char *val = NULL;
    int capt_id;

    if (ucl_object_type(obj) == UCL_INT) {
        capt_id = ucl_object_toint(obj);
    } else {
        val = ucl_object_tostring_forced(obj);
        RTPP_LOG(log, RTPP_LOG_ERR, "error in config file; invalid value for capt_id in section '%s': '%s'",
            ucl_object_key(obj), val);
        return (false);
    }
    if (capt_id < 0 || capt_id > 0xffffffff) {
        RTPP_LOG(log, RTPP_LOG_ERR, "error in config file; invalid value for capt_id in section '%s': %d",
            ucl_object_key(obj), capt_id);
        return (false);
    }
    target->capt_id = capt_id;
    return (true);
}

static struct rtpp_module_conf _rtpp_arh_conf = {
    .conf_data = NULL,
    .conf_map = {
        { "load", NULL }, /* The "load" is set when the hep_ctx is created */
        { "capt_host", (conf_helper_func) conf_set_capt_host },
        { "capt_port", (conf_helper_func) conf_set_capt_port },
        { "capt_ptype", (conf_helper_func) conf_set_capt_ptype },
        { "capt_id", (conf_helper_func) conf_set_capt_id },
        { NULL, (conf_helper_func) rtpp_ucl_set_unknown }
    }
};

struct rtpp_module_conf *rtpp_arh_conf = &_rtpp_arh_conf;
