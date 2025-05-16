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

#pragma once

#define MODULE_API_REVISION 12

struct rtpp_cfg;
struct rtpp_module_priv;
struct rtpp_module_conf;
struct rtpp_acct_handlers;
struct rtpp_cplane_handlers;
struct rtpp_wthr_handlers;
struct rtpp_minfo;

#if !defined(MODULE_IF_CODE)
#include <sys/types.h>
#include "rtpp_types.h"
#endif

DEFINE_RAW_METHOD(rtpp_module_ctor, struct rtpp_module_priv *,
  const struct rtpp_cfg *, struct rtpp_minfo *);
DEFINE_RAW_METHOD(rtpp_module_get_mconf, struct rtpp_module_conf *, void);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_config, int,
  struct rtpp_module_conf *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_dtor, void);

#include <stdarg.h>

#if defined(RTPP_CHECK_LEAKS)
DEFINE_RAW_METHOD(rtpp_module_malloc, void *, size_t,  void *, HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_zmalloc, void *, size_t,  void *, HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_rzmalloc, void *, size_t, size_t, void *, HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_free, void, void *, void *, HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_realloc, void *, void *, size_t,   void *,
  HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_strdup, char *, const char *,  void *,
  HERETYPE);
DEFINE_RAW_METHOD(rtpp_module_asprintf, int, char **, void *, HERETYPE,
   const char *, ...) __attribute__ ((format (printf, 4, 5)));;
DEFINE_RAW_METHOD(rtpp_module_vasprintf, int, char **, const char *,
   void *, HERETYPE, va_list);;
#else
DEFINE_RAW_METHOD(rtpp_module_malloc, void *, size_t);
DEFINE_RAW_METHOD(rtpp_module_zmalloc, void *, size_t);
DEFINE_RAW_METHOD(rtpp_module_rzmalloc, void *, size_t, size_t);
DEFINE_RAW_METHOD(rtpp_module_free, void, void *);
DEFINE_RAW_METHOD(rtpp_module_realloc, void *, void *, size_t);
DEFINE_RAW_METHOD(rtpp_module_strdup, char *, const char *);
DEFINE_RAW_METHOD(rtpp_module_asprintf, int, char **, const char *, ...)
  __attribute__ ((format (printf, 2, 3)));
DEFINE_RAW_METHOD(rtpp_module_vasprintf, int, char **, const char *, va_list);
#endif

#if !defined(MODULE_IF_CODE)

#if defined(LIBRTPPROXY)
#include "rtpp_module_if_static.h"
#define EXPAND_AND_CONCAT(a, b) a##b
#define CONCAT(a, b) EXPAND_AND_CONCAT(a, b)
#define RTPP_MOD_SELF CONCAT(rtpp_module_, RTPP_MOD_NAME)
extern const struct rtpp_minfo RTPP_MOD_SELF;
#else
#define RTPP_MOD_SELF (rtpp_module)
#endif

#define _MMFN (*(RTPP_MOD_SELF.fn))

#if defined(RTPP_CHECK_LEAKS)

#define _MMDEB *(RTPP_MOD_SELF.memdeb_p)

#define mod_malloc(n) _MMFN._malloc((n), _MMDEB, \
  HEREVAL)
#define mod_zmalloc(n) _MMFN._zmalloc((n), _MMDEB, \
  HEREVAL)
#define mod_rzmalloc(n, m) _MMFN._rzmalloc((n), (m), _MMDEB, \
  HEREVAL)
#define mod_free(p) _MMFN._free((p), _MMDEB, \
  HEREVAL)
#define mod_realloc(p,n) _MMFN._realloc((p), (n), _MMDEB, \
  HEREVAL)
#define mod_strdup(p) _MMFN._strdup((p), _MMDEB, \
  HEREVAL)
#define mod_asprintf(pp, fmt, args...) _MMFN._asprintf((pp), \
  _MMDEB, HEREVAL, (fmt), ## args)
#define mod_vasprintf(pp, fmt, vl) _MMFN._vasprintf((pp), (fmt), \
  _MMDEB, HEREVAL, (vl))
#else
#define mod_malloc(n) _MMFN._malloc((n))
#define mod_zmalloc(n) _MMFN._zmalloc((n))
#define mod_rzmalloc(n, m) _MMFN._rzmalloc((n), m)
#define mod_free(p) _MMFN._free((p))
#define mod_realloc(p,n) _MMFN._realloc((p), (n))
#define mod_strdup(p) _MMFN._strdup((p))
#define mod_asprintf(pp, fmt, args...) _MMFN._asprintf((pp), (fmt), ## args)
#define mod_vasprintf(pp, fmt, vl) _MMFN._vasprintf((pp), (fmt), (vl))

#endif /* RTPP_CHECK_LEAKS */
#endif /* !MODULE_IF_CODE */

struct api_version {
    int rev;
    size_t mi_size;
    const char *build;
};

struct rtpp_mdescr {
    struct api_version ver;
    const char *name;
    const char *author;
    const char *copyright;
    const char *maintainer;
    unsigned int module_id;
};

struct rtpp_mhandlers {
    rtpp_module_ctor_t ctor;
    rtpp_module_dtor_t dtor;
    rtpp_module_get_mconf_t get_mconf;
    rtpp_module_config_t config;
};

#include <pthread.h>

struct rtpp_wthrdata {
    struct rtpp_wi *sigterm;
    pthread_t thread_id;
    struct rtpp_queue *mod_q;
    struct rtpp_module_priv *mpvt;
};

struct rtpp_modids {
    unsigned int instance_id;
    unsigned int module_idx;
};

struct rtpp_minfo_fset {
    rtpp_module_malloc_t _malloc;
    rtpp_module_zmalloc_t _zmalloc;
    rtpp_module_rzmalloc_t _rzmalloc;
    rtpp_module_free_t _free;
    rtpp_module_realloc_t _realloc;
    rtpp_module_strdup_t _strdup;
    rtpp_module_asprintf_t _asprintf;
    rtpp_module_vasprintf_t _vasprintf;
    const void *auxp[];
};

DECLARE_CLASS_PUBTYPE(rtpp_minfo, {
    /* Upper half, filled by the module */
    union {
        struct {
            struct rtpp_mdescr descr;
            struct rtpp_mhandlers proc;
            const struct rtpp_acct_handlers *aapi;
            const struct rtpp_cplane_handlers *capi;
            const struct rtpp_wthr_handlers *wapi;
            void **memdeb_p;
            struct rtpp_minfo_fset *fn;
        };
        char upper[0];
    };
    /* Lower half, filled by the core */
    union {
        struct {
            const struct rtpp_modids *ids;
            struct rtpp_log *log;
            struct rtpp_refcnt *super_rcnt;
            struct rtpp_wthrdata wthr;
            void *memdeb;
        };
        char lower[0];
    };
});

extern const struct rtpp_minfo rtpp_module RTPP_EXPORT;

#define MI_VER_INIT() { \
    .rev = MODULE_API_REVISION, \
    .mi_size = sizeof(rtpp_module), \
    .build = RTPP_SW_VERSION}
#define MI_VER_CHCK(sptr) ( \
  (sptr)->descr.ver.rev == MODULE_API_REVISION && \
  (sptr)->descr.ver.mi_size == sizeof(struct rtpp_minfo) && \
  strcmp((sptr)->descr.ver.build, RTPP_SW_VERSION) == 0)
