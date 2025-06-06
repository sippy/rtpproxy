/* Auto-generated by genfincode.sh - DO NOT EDIT! */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define RTPP_FINCODE
#include "rtpp_types.h"
#include "rtpp_debug.h"
#include "rtpp_log_obj.h"
#include "rtpp_log_obj_fin.h"
#if defined(RTPP_DEBUG)
static void rtpp_log_ewrite_fin(void *pub) {
    fprintf(stderr, "Method rtpp_log@%p::errwrite (rtpp_log_ewrite) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_log_setlevel_fin(void *pub) {
    fprintf(stderr, "Method rtpp_log@%p::setlevel (rtpp_log_setlevel) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_log_start_fin(void *pub) {
    fprintf(stderr, "Method rtpp_log@%p::start (rtpp_log_start) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
static void rtpp_log_write_fin(void *pub) {
    fprintf(stderr, "Method rtpp_log@%p::genwrite (rtpp_log_write) is invoked after destruction\x0a", pub);
    RTPP_AUTOTRAP();
}
void rtpp_log_fin(struct rtpp_log *pub) {
    RTPP_DBG_ASSERT(pub->errwrite != (rtpp_log_ewrite_t)NULL);
    RTPP_DBG_ASSERT(pub->errwrite != (rtpp_log_ewrite_t)&rtpp_log_ewrite_fin);
    pub->errwrite = (rtpp_log_ewrite_t)&rtpp_log_ewrite_fin;
    RTPP_DBG_ASSERT(pub->setlevel != (rtpp_log_setlevel_t)NULL);
    RTPP_DBG_ASSERT(pub->setlevel != (rtpp_log_setlevel_t)&rtpp_log_setlevel_fin);
    pub->setlevel = (rtpp_log_setlevel_t)&rtpp_log_setlevel_fin;
    RTPP_DBG_ASSERT(pub->start != (rtpp_log_start_t)NULL);
    RTPP_DBG_ASSERT(pub->start != (rtpp_log_start_t)&rtpp_log_start_fin);
    pub->start = (rtpp_log_start_t)&rtpp_log_start_fin;
    RTPP_DBG_ASSERT(pub->genwrite != (rtpp_log_write_t)NULL);
    RTPP_DBG_ASSERT(pub->genwrite != (rtpp_log_write_t)&rtpp_log_write_fin);
    pub->genwrite = (rtpp_log_write_t)&rtpp_log_write_fin;
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
rtpp_log_fintest()
{
    int naborts_s;

    struct {
        struct rtpp_log pub;
    } *tp;

    naborts_s = _naborts;
    tp = rtpp_rzmalloc(sizeof(*tp), offsetof(typeof(*tp), pub.rcnt));
    assert(tp != NULL);
    assert(tp->pub.rcnt != NULL);
    tp->pub.errwrite = (rtpp_log_ewrite_t)((void *)0x1);
    tp->pub.setlevel = (rtpp_log_setlevel_t)((void *)0x1);
    tp->pub.start = (rtpp_log_start_t)((void *)0x1);
    tp->pub.genwrite = (rtpp_log_write_t)((void *)0x1);
    CALL_SMETHOD(tp->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_log_fin,
      &tp->pub);
    RTPP_OBJ_DECREF(&(tp->pub));
    CALL_TFIN(&tp->pub, errwrite);
    CALL_TFIN(&tp->pub, setlevel);
    CALL_TFIN(&tp->pub, start);
    CALL_TFIN(&tp->pub, genwrite);
    assert((_naborts - naborts_s) == 4);
}
DATA_SET(rtpp_fintests, rtpp_log_fintest);
#endif /* RTPP_FINTEST */
