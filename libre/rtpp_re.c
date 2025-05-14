#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"

struct ice_candpair;
struct tcp_conn;
struct sa;
struct udp_sock;
struct mbuf;
struct tmr;

typedef void (mem_destroy_h)(void *data);

void
tmr_init(struct tmr *tmr)
{
    /* Not implemented */
    /* nop() */
}

uint64_t
tmr_jiffies(void)
{
    /* Not implemented */
    return 0;
}

void
tmr_cancel(struct tmr *tmr)
{
    /* Not implemented */
    /* nop() */
}

void *
mem_realloc(void *data, size_t size)
{
    /* Not implemented */
    abort();
}

struct re_mem {
    struct rtpp_refcnt *rcnt;
    long long data[0];
};

void *
mem_zalloc(size_t size, mem_destroy_h *dh)
{
    struct re_mem *pvt;
    void *rp;

    pvt = rtpp_rzmalloc(sizeof(*pvt) + size, offsetof(typeof(*pvt), rcnt));
    if (pvt == NULL)
        return (NULL);
    rp = (void *)pvt->data;
    if (dh != NULL) {
        CALL_SMETHOD(pvt->rcnt, attach, (rtpp_refcnt_dtor_t)dh, rp);
    }
    return (rp);
}

#define D2P(d) (struct re_mem *)((char *)(d) - offsetof(struct re_mem, data))

void *
mem_deref(void *data)
{
    if (data != NULL) {
        struct re_mem *pvt = D2P(data);
        RTPP_OBJ_DECREF(pvt);
    }
    return (NULL);
}

void *
mem_ref(void *data)
{
    struct re_mem *pvt = D2P(data);

    RTPP_OBJ_INCREF(pvt);
    return (data);
}
