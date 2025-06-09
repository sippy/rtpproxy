/*
 * Copyright (c) 2014-2023 Sippy Software, Inc., http://www.sippysoft.com
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

#define RTPP_UID_NONE ((uint64_t)0)

struct rtpp_type_linkable {
#if 0
    unsigned int rtpp_type;
#endif
    struct rtpp_type_linkable *next;
    char type_data[0];
};

#define DECLARE_CLASS(rot_name, init_args...) \
    struct rot_name; \
    typedef struct rot_name rot_name##_rot; \
    rot_name##_rot *rot_name##_ctor(init_args)

#if defined(RTPP_DEBUG)
#define DECLARE_CLASS_PUBTYPE(rot_name, custom_struct) \
    struct rtpp_refcnt; \
    struct rot_name {  \
        struct rtpp_refcnt *rcnt; \
        const struct rot_name##_smethods * smethods; \
        struct custom_struct; \
    };
#else
#define DECLARE_CLASS_PUBTYPE(rot_name, custom_struct) \
    struct rtpp_refcnt; \
    struct rot_name {  \
        struct rtpp_refcnt *rcnt; \
        struct custom_struct; \
    };
#endif
#define DECLARE_METHOD(class, func, rval, args...) typedef rval (*func##_t)(class##_rot *, ## args)
#define DECLARE_SMETHODS(rot_name) \
    struct rot_name##_smethods
#define DEFINE_SMETHODS(rot_name, methods...) \
    static const struct rot_name##_smethods _##rot_name##_smethods = { \
        methods \
     }; \
     const struct rot_name##_smethods * const rot_name##_smethods = &_##rot_name##_smethods;
#if defined(RTPP_DEBUG)
#define PUBINST_FININIT(pub_inst, pvt_inst, dtor) \
    (pub_inst)->smethods = GET_SMETHODS(pub_inst); \
    CALL_SMETHOD((pub_inst)->rcnt, attach, (rtpp_refcnt_dtor_t)(dtor), \
      pvt_inst);
#else
#define PUBINST_FININIT(pub_inst, pvt_inst, dtor) \
    CALL_SMETHOD((pub_inst)->rcnt, attach, (rtpp_refcnt_dtor_t)(dtor), \
      pvt_inst);
#endif

#define DEFINE_METHOD(class, func, rval, args...) typedef rval (*func##_t)(struct class *, ## args)
#define DEFINE_RAW_METHOD(func, rval, args...) typedef rval (*func##_t)(args)
#define METHOD_ENTRY(func, epname) func##_t epname
#define CALL_METHOD(obj, method, args...) (obj)->method(obj, ## args)

#define RTPP_EXPORT __attribute__((visibility("default")))

extern const struct rtpp_refcnt_smethods * const rtpp_refcnt_smethods RTPP_EXPORT;
extern const struct rtpp_pearson_perfect_smethods * const rtpp_pearson_perfect_smethods;
extern const struct rtpp_netaddr_smethods * const rtpp_netaddr_smethods RTPP_EXPORT;
extern const struct rtpp_server_smethods * const rtpp_server_smethods;
extern const struct rtpp_stats_smethods * const rtpp_stats_smethods RTPP_EXPORT;
extern const struct rtpp_timed_smethods * const rtpp_timed_smethods RTPP_EXPORT;
extern const struct rtpp_stream_smethods * const rtpp_stream_smethods RTPP_EXPORT;
extern const struct rtpp_pcount_smethods * const rtpp_pcount_smethods RTPP_EXPORT;
extern const struct rtpp_record_smethods * const rtpp_record_smethods;
extern const struct rtpp_hash_table_smethods * const rtpp_hash_table_smethods;
extern const struct rtpp_weakref_smethods * const rtpp_weakref_smethods RTPP_EXPORT;
extern const struct rtpp_analyzer_smethods * const rtpp_analyzer_smethods;
extern const struct rtpp_pcnt_strm_smethods * const rtpp_pcnt_strm_smethods RTPP_EXPORT;
extern const struct rtpp_ttl_smethods * const rtpp_ttl_smethods RTPP_EXPORT;
extern const struct rtpp_pipe_smethods * const rtpp_pipe_smethods;
extern const struct rtpp_ringbuf_smethods * const rtpp_ringbuf_smethods;
extern const struct rtpp_sessinfo_smethods * const rtpp_sessinfo_smethods RTPP_EXPORT;
extern const struct rtpp_rw_lock_smethods * const rtpp_rw_lock_smethods;
extern const struct rtpp_proc_servers_smethods * const rtpp_proc_servers_smethods;
extern const struct rtpp_proc_wakeup_smethods * const rtpp_proc_wakeup_smethods;
extern const struct pproc_manager_smethods * const pproc_manager_smethods RTPP_EXPORT;
extern const struct rtpp_dtls_conn_smethods * const rtpp_dtls_conn_smethods;
extern const struct rtpp_socket_smethods * const rtpp_socket_smethods;
extern const struct rtpp_refproxy_smethods * const rtpp_refproxy_smethods RTPP_EXPORT;
extern const struct rtpc_reply_smethods * const rtpc_reply_smethods;
extern const struct rtpp_genuid_smethods * const rtpp_genuid_smethods;

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
    struct rtpp_hash_table *: rtpp_hash_table_smethods, \
    struct rtpp_weakref *: rtpp_weakref_smethods, \
    struct rtpp_analyzer *: rtpp_analyzer_smethods, \
    struct rtpp_pcnt_strm *: rtpp_pcnt_strm_smethods, \
    struct rtpp_ttl *: rtpp_ttl_smethods, \
    struct rtpp_pipe *: rtpp_pipe_smethods, \
    struct rtpp_ringbuf *: rtpp_ringbuf_smethods, \
    struct rtpp_sessinfo *: rtpp_sessinfo_smethods, \
    struct rtpp_rw_lock *: rtpp_rw_lock_smethods, \
    struct rtpp_proc_servers *: rtpp_proc_servers_smethods, \
    struct rtpp_proc_wakeup *: rtpp_proc_wakeup_smethods, \
    struct pproc_manager *: pproc_manager_smethods, \
    struct rtpp_dtls_conn *: rtpp_dtls_conn_smethods, \
    struct rtpp_socket *: rtpp_socket_smethods, \
    struct rtpp_refproxy *: rtpp_refproxy_smethods, \
    struct rtpc_reply *: rtpc_reply_smethods, \
    struct rtpp_genuid *: rtpp_genuid_smethods \
)

#if defined(RTPP_DEBUG)
#define GET_SMETHOD(obj, method) ((obj)->smethods->method)
#else
#define GET_SMETHOD(obj, method) (GET_SMETHODS(obj)->method)
#endif
#define CALL_SMETHOD(obj, method, args...) GET_SMETHOD(obj, method)(obj, ## args)

#ifdef __clang__
    #define typeof(x) __typeof__(x)
#else
    // Might even check for __GNUC__?
    #define typeof(x) __typeof(x)
#endif

#define PVT_RCOFFS(pvtp) (offsetof(typeof(*(pvtp)), pub) + offsetof(typeof((pvtp)->pub), rcnt))
#define PUB_RCOFFS(pub) offsetof(typeof(*(pub)), rcnt)

#define PUB2PVT(pubp, pvtp) \
  (pvtp) = (typeof(pvtp))((char *)(pubp) - offsetof(typeof(*(pvtp)), pub))

#define CONST(p) ((const typeof(*p) *)(p))

#define RTPP_OBJ_INCREF(obj) RC_INCREF((obj)->rcnt)
#define RTPP_OBJ_DECREF(obj) RC_DECREF((obj)->rcnt)
#define RTPP_OBJ_DTOR_ATTACH(obj, f, p) CALL_SMETHOD((obj)->rcnt, attach, \
  (rtpp_refcnt_dtor_t)(f), (p))
#define RTPP_OBJ_DTOR_ATTACH_RC(obj, rc) CALL_SMETHOD((obj)->rcnt, attach_rc, \
  (rc))
#define RTPP_OBJ_DTOR_ATTACH_OBJ(obj, obj1) CALL_SMETHOD((obj)->rcnt, attach_rc, \
  (obj1)->rcnt)
#define RTPP_OBJ_BORROW(bob, lob) \
    do { /* Attach first, then increase, the "lob: counter might have */ \
         /* certain optimizations for the count == 1 case             */ \
        RTPP_OBJ_DTOR_ATTACH_RC((bob), (lob)->rcnt); \
        RTPP_OBJ_INCREF(lob); \
    } while (0)

#define DEFINE_CB_STRUCT(functype) \
    typedef struct { \
        functype##_cb_t func; \
        void *arg; \
    } functype##_cb_s;
