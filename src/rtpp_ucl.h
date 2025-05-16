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

#pragma once

struct ucl_object_s;
struct rtpp_log;

typedef struct ucl_object_s ucl_object_t;

/*
 * Config parser helper callback function pointer alias
 */
DEFINE_RAW_METHOD(conf_helper, bool, struct rtpp_log *, const ucl_object_t *,
  const ucl_object_t *, void *);

/*
 * Config parser helper callback map. Maps UCL keys to callback functions that
 * parse the key and store the value in the correct struct member
 */
typedef struct conf_helper_callback_map {
    const char *conf_key;
    conf_helper_t callback;
} conf_helper_map;

struct rtpp_module_conf {
    struct rtpp_refcnt *rcnt;
    void *conf_data;
    const conf_helper_map *conf_map;
};

bool rtpp_ucl_set_unknown(struct rtpp_log *, const ucl_object_t *top,
  const ucl_object_t *obj, void *target) RTPP_EXPORT;
const char *r_ucl_object_tostring_forced(const ucl_object_t *obj)
  RTPP_EXPORT;
ucl_type_t r_ucl_object_type(const ucl_object_t *obj)
  RTPP_EXPORT;
int64_t r_ucl_object_toint(const ucl_object_t *obj)
  RTPP_EXPORT;
const char * r_ucl_object_key(const ucl_object_t *obj)
  RTPP_EXPORT;
#if !defined(_RTPP_UCL_C)
#define ucl_object_tostring_forced r_ucl_object_tostring_forced
#define ucl_object_type r_ucl_object_type
#define ucl_object_toint r_ucl_object_toint
#define ucl_object_key r_ucl_object_key
#endif
