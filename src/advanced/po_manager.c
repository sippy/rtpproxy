#include <stddef.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"

#include "advanced/po_manager.h"
#include "advanced/packet_observer.h"

#define MAX_OBSERVERS 4

#define PUB2PVT(pubp, pvtp) \
    (pvtp) = (typeof(pvtp))((char *)(pubp) - offsetof(typeof(*(pvtp)), pub))

struct po_manager_pvt {
    struct po_manager pub;
    struct packet_observer_if observers[MAX_OBSERVERS + 1];
};

static int rtpp_po_mgr_register(struct po_manager *, const struct packet_observer_if *);

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
    pvt->pub.reg = rtpp_po_mgr_register;
    CALL_SMETHOD(pvt->pub.rcnt, attach, (rtpp_refcnt_dtor_t)&rtpp_po_mgr_dtor,
      pvt);
    return (&(pvt->pub));
}

static int
rtpp_po_mgr_register(struct po_manager *pub, const struct packet_observer_if *ip)
{
    int i;
    struct po_manager_pvt *pvt;

    PUB2PVT(pub, pvt);
    for (i = 0; i < MAX_OBSERVERS; i++)
        if (pvt->observers[i].taste == NULL)
            break;
    if (i >= MAX_OBSERVERS)
        return (-1);
    pvt->observers[i] = *ip;
    return (0);
}
