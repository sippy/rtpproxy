/* Auto-generated by genfincode.sh - DO NOT EDIT! */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define RTPP_FINCODE
#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_modman.h"
#include "rtpp_modman_fin.h"
#if defined(RTPP_DEBUG)
static void rtpp_modman_do_acct_fin(void *pub) {
    fprintf(stderr, "Method rtpp_modman@%p::do_acct (rtpp_modman_do_acct) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_modman_get_next_id_fin(void *pub) {
    fprintf(stderr, "Method rtpp_modman@%p::get_next_id (rtpp_modman_get_next_id) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_modman_get_ul_subc_h_fin(void *pub) {
    fprintf(stderr, "Method rtpp_modman@%p::get_ul_subc_h (rtpp_modman_get_ul_subc_h) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_modman_insert_fin(void *pub) {
    fprintf(stderr, "Method rtpp_modman@%p::insert (rtpp_modman_insert) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_modman_startall_fin(void *pub) {
    fprintf(stderr, "Method rtpp_modman@%p::startall (rtpp_modman_startall) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
void rtpp_modman_fin(struct rtpp_modman *pub) {
    RTPP_DBG_ASSERT(pub->do_acct != (rtpp_modman_do_acct_t)NULL);
    RTPP_DBG_ASSERT(pub->do_acct != (rtpp_modman_do_acct_t)&rtpp_modman_do_acct_fin);
    pub->do_acct = (rtpp_modman_do_acct_t)&rtpp_modman_do_acct_fin;
    RTPP_DBG_ASSERT(pub->get_next_id != (rtpp_modman_get_next_id_t)NULL);
    RTPP_DBG_ASSERT(pub->get_next_id != (rtpp_modman_get_next_id_t)&rtpp_modman_get_next_id_fin);
    pub->get_next_id = (rtpp_modman_get_next_id_t)&rtpp_modman_get_next_id_fin;
    RTPP_DBG_ASSERT(pub->get_ul_subc_h != (rtpp_modman_get_ul_subc_h_t)NULL);
    RTPP_DBG_ASSERT(pub->get_ul_subc_h != (rtpp_modman_get_ul_subc_h_t)&rtpp_modman_get_ul_subc_h_fin);
    pub->get_ul_subc_h = (rtpp_modman_get_ul_subc_h_t)&rtpp_modman_get_ul_subc_h_fin;
    RTPP_DBG_ASSERT(pub->insert != (rtpp_modman_insert_t)NULL);
    RTPP_DBG_ASSERT(pub->insert != (rtpp_modman_insert_t)&rtpp_modman_insert_fin);
    pub->insert = (rtpp_modman_insert_t)&rtpp_modman_insert_fin;
    RTPP_DBG_ASSERT(pub->startall != (rtpp_modman_startall_t)NULL);
    RTPP_DBG_ASSERT(pub->startall != (rtpp_modman_startall_t)&rtpp_modman_startall_fin);
    pub->startall = (rtpp_modman_startall_t)&rtpp_modman_startall_fin;
}
#endif /* RTPP_DEBUG */
#if defined(RTPP_FINTEST)
#include <assert.h>
#include <stddef.h>
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_linker_set.h"
#define CALL_TFIN(pub, fn) ((void (*)(typeof(pub)))((pub)->fn))(pub)

void
rtpp_modman_fintest()
{
    int naborts_s;

    struct {
        struct rtpp_modman pub;
    } *tp;

    naborts_s = _naborts;
    tp = rtpp_rzmalloc(sizeof(*tp), offsetof(typeof(*tp), pub.rcnt));
    assert(tp != NULL);
    assert(tp->pub.rcnt != NULL);
    tp->pub.do_acct = (rtpp_modman_do_acct_t)((void *)0x1);
    tp->pub.get_next_id = (rtpp_modman_get_next_id_t)((void *)0x1);
    tp->pub.get_ul_subc_h = (rtpp_modman_get_ul_subc_h_t)((void *)0x1);
    tp->pub.insert = (rtpp_modman_insert_t)((void *)0x1);
    tp->pub.startall = (rtpp_modman_startall_t)((void *)0x1);
    CALL_SMETHOD(tp->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_modman_fin,
      &tp->pub);
    RTPP_OBJ_DECREF(&(tp->pub));
    CALL_TFIN(&tp->pub, do_acct);
    CALL_TFIN(&tp->pub, get_next_id);
    CALL_TFIN(&tp->pub, get_ul_subc_h);
    CALL_TFIN(&tp->pub, insert);
    CALL_TFIN(&tp->pub, startall);
    assert((_naborts - naborts_s) == 5);
}
DATA_SET(rtpp_fintests, rtpp_modman_fintest);
#endif /* RTPP_FINTEST */
