/* Auto-generated by genfincode_stat.sh - DO NOT EDIT! */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define RTPP_FINCODE
#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_netaddr.h"
#include "rtpp_netaddr_fin.h"
static void rtpp_netaddr_cmp_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::cmp (rtpp_netaddr_cmp) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_cmphost_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::cmphost (rtpp_netaddr_cmphost) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_copy_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::copy (rtpp_netaddr_copy) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_get_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::get (rtpp_netaddr_get) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_isaddrseq_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::isaddrseq (rtpp_netaddr_isaddrseq) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_isempty_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::isempty (rtpp_netaddr_isempty) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_set_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::set (rtpp_netaddr_set) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_netaddr_sip_print_fin(void *pub) {
    fprintf(stderr, "Method rtpp_netaddr@%p::sip_print (rtpp_netaddr_sip_print) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static const struct rtpp_netaddr_smethods rtpp_netaddr_smethods_fin = {
    .cmp = (rtpp_netaddr_cmp_t)&rtpp_netaddr_cmp_fin,
    .cmphost = (rtpp_netaddr_cmphost_t)&rtpp_netaddr_cmphost_fin,
    .copy = (rtpp_netaddr_copy_t)&rtpp_netaddr_copy_fin,
    .get = (rtpp_netaddr_get_t)&rtpp_netaddr_get_fin,
    .isaddrseq = (rtpp_netaddr_isaddrseq_t)&rtpp_netaddr_isaddrseq_fin,
    .isempty = (rtpp_netaddr_isempty_t)&rtpp_netaddr_isempty_fin,
    .set = (rtpp_netaddr_set_t)&rtpp_netaddr_set_fin,
    .sip_print = (rtpp_netaddr_sip_print_t)&rtpp_netaddr_sip_print_fin,
};
void rtpp_netaddr_fin(struct rtpp_netaddr *pub) {
    RTPP_DBG_ASSERT(pub->smethods->cmp != (rtpp_netaddr_cmp_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->cmphost != (rtpp_netaddr_cmphost_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->copy != (rtpp_netaddr_copy_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->get != (rtpp_netaddr_get_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->isaddrseq != (rtpp_netaddr_isaddrseq_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->isempty != (rtpp_netaddr_isempty_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->set != (rtpp_netaddr_set_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods->sip_print != (rtpp_netaddr_sip_print_t)NULL);
    RTPP_DBG_ASSERT(pub->smethods != &rtpp_netaddr_smethods_fin &&
      pub->smethods != NULL);
    pub->smethods = &rtpp_netaddr_smethods_fin;
}
#if defined(RTPP_FINTEST)
#include <assert.h>
#include <stddef.h>
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_linker_set.h"
#define CALL_TFIN(pub, fn) ((void (*)(typeof(pub)))((pub)->smethods->fn))(pub)

void
rtpp_netaddr_fintest()
{
    int naborts_s;

    struct {
        struct rtpp_netaddr pub;
    } *tp;

    naborts_s = _naborts;
    tp = rtpp_rzmalloc(sizeof(*tp), offsetof(typeof(*tp), pub.rcnt));
    assert(tp != NULL);
    assert(tp->pub.rcnt != NULL);
    static const struct rtpp_netaddr_smethods dummy = {
        .cmp = (rtpp_netaddr_cmp_t)((void *)0x1),
        .cmphost = (rtpp_netaddr_cmphost_t)((void *)0x1),
        .copy = (rtpp_netaddr_copy_t)((void *)0x1),
        .get = (rtpp_netaddr_get_t)((void *)0x1),
        .isaddrseq = (rtpp_netaddr_isaddrseq_t)((void *)0x1),
        .isempty = (rtpp_netaddr_isempty_t)((void *)0x1),
        .set = (rtpp_netaddr_set_t)((void *)0x1),
        .sip_print = (rtpp_netaddr_sip_print_t)((void *)0x1),
    };
    tp->pub.smethods = &dummy;
    CALL_SMETHOD(tp->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_netaddr_fin,
      &tp->pub);
    RTPP_OBJ_DECREF(&(tp->pub));
    CALL_TFIN(&tp->pub, cmp);
    CALL_TFIN(&tp->pub, cmphost);
    CALL_TFIN(&tp->pub, copy);
    CALL_TFIN(&tp->pub, get);
    CALL_TFIN(&tp->pub, isaddrseq);
    CALL_TFIN(&tp->pub, isempty);
    CALL_TFIN(&tp->pub, set);
    CALL_TFIN(&tp->pub, sip_print);
    assert((_naborts - naborts_s) == 8);
}
DATA_SET(rtpp_fintests, rtpp_netaddr_fintest);
#endif /* RTPP_FINTEST */
