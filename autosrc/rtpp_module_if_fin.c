/* Auto-generated by genfincode.sh - DO NOT EDIT! */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define RTPP_FINCODE
#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_module_if.h"
#include "rtpp_module_if_fin.h"
#if defined(RTPP_DEBUG)
static void rtpp_module_if_construct_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::construct (rtpp_module_if_construct) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_do_acct_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::do_acct (rtpp_module_if_do_acct) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_do_acct_rtcp_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::do_acct_rtcp (rtpp_module_if_do_acct_rtcp) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_get_mconf_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::get_mconf (rtpp_module_if_get_mconf) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_kaput_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::kaput (rtpp_module_if_kaput) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_load_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::load (rtpp_module_if_load) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_module_if_start_fin(void *pub) {
    fprintf(stderr, "Method rtpp_module_if@%p::start (rtpp_module_if_start) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
void rtpp_module_if_fin(struct rtpp_module_if *pub) {
    RTPP_DBG_ASSERT(pub->construct != (rtpp_module_if_construct_t)NULL);
    RTPP_DBG_ASSERT(pub->construct != (rtpp_module_if_construct_t)&rtpp_module_if_construct_fin);
    pub->construct = (rtpp_module_if_construct_t)&rtpp_module_if_construct_fin;
    RTPP_DBG_ASSERT(pub->do_acct != (rtpp_module_if_do_acct_t)NULL);
    RTPP_DBG_ASSERT(pub->do_acct != (rtpp_module_if_do_acct_t)&rtpp_module_if_do_acct_fin);
    pub->do_acct = (rtpp_module_if_do_acct_t)&rtpp_module_if_do_acct_fin;
    RTPP_DBG_ASSERT(pub->do_acct_rtcp != (rtpp_module_if_do_acct_rtcp_t)NULL);
    RTPP_DBG_ASSERT(pub->do_acct_rtcp != (rtpp_module_if_do_acct_rtcp_t)&rtpp_module_if_do_acct_rtcp_fin);
    pub->do_acct_rtcp = (rtpp_module_if_do_acct_rtcp_t)&rtpp_module_if_do_acct_rtcp_fin;
    RTPP_DBG_ASSERT(pub->get_mconf != (rtpp_module_if_get_mconf_t)NULL);
    RTPP_DBG_ASSERT(pub->get_mconf != (rtpp_module_if_get_mconf_t)&rtpp_module_if_get_mconf_fin);
    pub->get_mconf = (rtpp_module_if_get_mconf_t)&rtpp_module_if_get_mconf_fin;
    RTPP_DBG_ASSERT(pub->kaput != (rtpp_module_if_kaput_t)NULL);
    RTPP_DBG_ASSERT(pub->kaput != (rtpp_module_if_kaput_t)&rtpp_module_if_kaput_fin);
    pub->kaput = (rtpp_module_if_kaput_t)&rtpp_module_if_kaput_fin;
    RTPP_DBG_ASSERT(pub->load != (rtpp_module_if_load_t)NULL);
    RTPP_DBG_ASSERT(pub->load != (rtpp_module_if_load_t)&rtpp_module_if_load_fin);
    pub->load = (rtpp_module_if_load_t)&rtpp_module_if_load_fin;
    RTPP_DBG_ASSERT(pub->start != (rtpp_module_if_start_t)NULL);
    RTPP_DBG_ASSERT(pub->start != (rtpp_module_if_start_t)&rtpp_module_if_start_fin);
    pub->start = (rtpp_module_if_start_t)&rtpp_module_if_start_fin;
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
rtpp_module_if_fintest()
{
    int naborts_s;

    struct {
        struct rtpp_module_if pub;
    } *tp;

    naborts_s = _naborts;
    tp = rtpp_rzmalloc(sizeof(*tp), offsetof(typeof(*tp), pub.rcnt));
    assert(tp != NULL);
    assert(tp->pub.rcnt != NULL);
    tp->pub.construct = (rtpp_module_if_construct_t)((void *)0x1);
    tp->pub.do_acct = (rtpp_module_if_do_acct_t)((void *)0x1);
    tp->pub.do_acct_rtcp = (rtpp_module_if_do_acct_rtcp_t)((void *)0x1);
    tp->pub.get_mconf = (rtpp_module_if_get_mconf_t)((void *)0x1);
    tp->pub.kaput = (rtpp_module_if_kaput_t)((void *)0x1);
    tp->pub.load = (rtpp_module_if_load_t)((void *)0x1);
    tp->pub.start = (rtpp_module_if_start_t)((void *)0x1);
    CALL_SMETHOD(tp->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_module_if_fin,
      &tp->pub);
    RTPP_OBJ_DECREF(&(tp->pub));
    CALL_TFIN(&tp->pub, construct);
    CALL_TFIN(&tp->pub, do_acct);
    CALL_TFIN(&tp->pub, do_acct_rtcp);
    CALL_TFIN(&tp->pub, get_mconf);
    CALL_TFIN(&tp->pub, kaput);
    CALL_TFIN(&tp->pub, load);
    CALL_TFIN(&tp->pub, start);
    assert((_naborts - naborts_s) == 7);
}
DATA_SET(rtpp_fintests, rtpp_module_if_fintest);
#endif /* RTPP_FINTEST */
