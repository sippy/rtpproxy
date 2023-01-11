/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef _RTPP_TYPES_H
#define _RTPP_TYPES_H

#define RTPP_UID_NONE ((uint64_t)0)

struct rtpp_type_linkable {
#if 0
    unsigned int rtpp_type;
#endif
    struct rtpp_type_linkable *next;
    char type_data[0];
};

#define DEFINE_METHOD(class, func, rval, args...) typedef rval (*func##_t)(struct class *, ## args)
#define DEFINE_RAW_METHOD(func, rval, args...) typedef rval (*func##_t)(args)
#define METHOD_ENTRY(func, epname) func##_t epname
#define CALL_METHOD(obj, method, args...) (obj)->method(obj, ## args)

extern const struct rtpp_refcnt_smethods * const rtpp_refcnt_smethods;
extern const struct rtpp_pearson_perfect_smethods * const rtpp_pearson_perfect_smethods;
extern const struct rtpp_netaddr_smethods * const rtpp_netaddr_smethods;
extern const struct rtpp_server_smethods * const rtpp_server_smethods;
extern const struct rtpp_stats_smethods * const rtpp_stats_smethods;
extern const struct rtpp_timed_smethods * const rtpp_timed_smethods;
extern const struct rtpp_stream_smethods * const rtpp_stream_smethods;
extern const struct rtpp_pcount_smethods * const rtpp_pcount_smethods;
extern const struct rtpp_record_smethods * const rtpp_record_smethods;
extern const struct pproc_manager_smethods * const pproc_manager_smethods;

#if defined(RTPP_DEBUG)
#define CALL_SMETHOD(obj, method, args...) (obj)->smethods->method(obj, ## args)
#else
#define GET_SMETHODS(obj) _Generic((obj), \
    struct rtpp_refcnt *: rtpp_refcnt_smethods, \
    struct rtpp_pearson_perfect *: rtpp_pearson_perfect_smethods, \
    struct rtpp_netaddr *: rtpp_netaddr_smethods, \
    struct rtpp_server *: rtpp_server_smethods, \
    struct rtpp_stats *: rtpp_stats_smethods, \
    struct rtpp_timed *: rtpp_timed_smethods, \
    struct rtpp_stream *: rtpp_stream_smethods, \
    struct rtpp_pcount *: rtpp_pcount_smethods, \
    struct rtpp_record *: rtpp_record_smethods, \
    struct pproc_manager *: pproc_manager_smethods \
)

#define CALL_SMETHOD(obj, method, args...) GET_SMETHODS(obj)->method(obj, ## args)
#endif

#ifdef __clang__
    #define typeof(x) __typeof__(x)
#else
    // Might even check for __GNUC__?
    #define typeof(x) __typeof(x)
#endif

#define PVT_RCOFFS(pvt) (size_t)(&(((typeof(pvt))NULL)->pub.rcnt))

#define PUB2PVT(pubp, pvtp) \
  (pvtp) = (typeof(pvtp))((char *)(pubp) - offsetof(typeof(*(pvtp)), pub))

#define CONST(p) ((const typeof(*p) *)(p))

#define RTPP_OBJ_INCREF(obj) RC_INCREF((obj)->rcnt)
#define RTPP_OBJ_DECREF(obj) RC_DECREF((obj)->rcnt)

#define DEFINE_CB_STRUCT(functype) \
    typedef struct { \
        functype##_cb_t func; \
        void *arg; \
    } functype##_cb_s;

#endif
