/*
 * Copyright (c) 2016-2018 Sippy Software, Inc., http://www.sippysoft.com
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

#define MODULE_API_REVISION 5

struct rtpp_cfg_stable;
struct rtpp_module_priv;
struct rtpp_acct;
struct rtpp_acct_rtcp;
struct rtpp_module_conf;

#if !defined(MODULE_IF_CODE)
#include <sys/types.h>
#include "rtpp_types.h"
#endif

DEFINE_METHOD(rtpp_cfg_stable, rtpp_module_ctor, struct rtpp_module_priv *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_get_mconf, struct rtpp_module_conf *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_config, int);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_dtor, void);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_on_session_end, void,
  struct rtpp_acct *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_on_rtcp_rcvd, void,
  struct rtpp_acct_rtcp *);

#include <stdarg.h>

DEFINE_RAW_METHOD(rtpp_module_malloc, void *, size_t,  void *, const char *,
  int, const char *);
DEFINE_RAW_METHOD(rtpp_module_zmalloc, void *, size_t,  void *, const char *,
  int, const char *);
DEFINE_RAW_METHOD(rtpp_module_free, void, void *, void *, const char *, int,
  const char *);
DEFINE_RAW_METHOD(rtpp_module_realloc, void *, void *, size_t,   void *,
  const char *, int, const char *);
DEFINE_RAW_METHOD(rtpp_module_strdup, char *, const char *,  void *,
  const char *, int, const char *);
DEFINE_RAW_METHOD(rtpp_module_asprintf, int, char **, const char *,
   void *, const char *, int, const char *, ...);
DEFINE_RAW_METHOD(rtpp_module_vasprintf, int, char **, const char *,
   void *, const char *, int, const char *, va_list);

#if !defined(MODULE_IF_CODE)
#define mod_malloc(n) rtpp_module._malloc((n), rtpp_module.memdeb_p, \
  __FILE__, __LINE__, __func__)
#define mod_zmalloc(n) rtpp_module._zmalloc((n), rtpp_module.memdeb_p, \
  __FILE__, __LINE__, __func__)
#define mod_free(p) rtpp_module._free((p), rtpp_module.memdeb_p, \
  __FILE__, __LINE__, __func__)
#define mod_realloc(p,n) rtpp_module._realloc((p), (n), rtpp_module.memdeb_p, \
  __FILE__, __LINE__, __func__)
#define mod_strdup(p) rtpp_module._strdup((p), rtpp_module.memdeb_p, \
  __FILE__, __LINE__, __func__)
#define mod_asprintf(pp, fmt, args...) rtpp_module._asprintf((pp), (fmt), \
  rtpp_module.memdeb_p, __FILE__, __LINE__, __func__, ## args)
#define mod_vasprintf(pp, fmt, vl) rtpp_module._vasprintf((pp), (fmt), \
  rtpp_module.memdeb_p, __FILE__, __LINE__, __func__, (vl))
#endif

#define mod_log(args...) CALL_METHOD(rtpp_module.log, write, __FUNCTION__, \
  ## args)
#define mod_elog(args...) CALL_METHOD(rtpp_module.log, ewrite, __FUNCTION__, \
  ## args)

struct api_version {
    int rev;
    size_t mi_size;
};

struct api_on_sess_end {
   int rev;
   size_t argsize;
   rtpp_module_on_session_end_t func;
};

struct api_on_rtcp_rcvd {
   int rev;
   size_t argsize;
   rtpp_module_on_rtcp_rcvd_t func;
};

struct rtpp_minfo {
    /* Upper half, filled by the module */
    struct api_version ver;
    const char *name;
    const char *author;
    const char *copyright;
    const char *maintainer;
    rtpp_module_ctor_t ctor;
    rtpp_module_dtor_t dtor;
    rtpp_module_get_mconf_t get_mconf;
    rtpp_module_config_t config;
    struct api_on_sess_end on_session_end;
    struct api_on_rtcp_rcvd on_rtcp_rcvd;
    /* Lower half, filled by the core */
    rtpp_module_malloc_t _malloc;
    rtpp_module_zmalloc_t _zmalloc;
    rtpp_module_free_t _free;
    rtpp_module_realloc_t _realloc;
    rtpp_module_strdup_t _strdup;
    rtpp_module_asprintf_t _asprintf;
    rtpp_module_vasprintf_t _vasprintf;
    void *memdeb_p;
    struct rtpp_log *log;
};

extern struct rtpp_minfo rtpp_module;

#define MI_VER_INIT() {.rev = MODULE_API_REVISION, .mi_size = sizeof(rtpp_module)}
#define MI_VER_CHCK(sptr) ((sptr)->ver.rev == MODULE_API_REVISION && \
  (sptr)->ver.mi_size == sizeof(struct rtpp_minfo))
