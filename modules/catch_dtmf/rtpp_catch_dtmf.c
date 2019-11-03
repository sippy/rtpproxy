#include <stddef.h>
#include <stdlib.h>

#include "rtpp_mallocs.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"

#include "../modules/catch_dtmf/rtpp_catch_dtmf.h"

struct rtpp_catch_dtmf_pvt {
    struct rtpp_catch_dtmf pub;
};

static void
rtpp_catch_dtmf_dtor(struct rtpp_catch_dtmf_pvt *pvt)
{

    free(pvt);
}

struct rtpp_catch_dtmf *
rtpp_catch_dtmf_ctor(struct po_manager *pomp)
{
    struct rtpp_catch_dtmf_pvt *pvt;
    struct rtpp_refcnt *rcnt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), &rcnt);
    if (pvt == NULL)
        return (NULL);
    pvt->pub.rcnt = rcnt;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_catch_dtmf_dtor,
      pvt);
    return (&(pvt->pub));
}
