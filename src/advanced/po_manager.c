#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"

#include "advanced/po_manager.h"
#include "advanced/packet_observer.h"

#define MAX_OBSERVERS 4

struct po_manager_pvt {
    struct po_manager pub;
    struct packet_observer_if observers[MAX_OBSERVERS + 1];
};

static void
rtpp_po_mgr_dtor(struct po_manager_pvt *pvt)
{

    free(pvt);
}

struct po_manager *
rtpp_po_mgr_ctor(void)
{
    struct po_manager_pvt *pvt;
    struct rtpp_refcnt *rcnt;

    pvt = rtpp_rzmalloc(sizeof(*pvt), &rcnt);
    if (pvt == NULL)
        return (NULL);
    pvt->pub.rcnt = rcnt;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_po_mgr_dtor,
      pvt);
    return (&(pvt->pub));
}
