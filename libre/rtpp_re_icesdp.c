#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define DEBUG_MODULE "icesdp"
#define DEBUG_LEVEL 5

struct stun_msg;

#include "re_dbg.h"
#include "re_fmt.h"
#include "re_sa.h"
#include "re_list.h"
#include "re_ice.h"
#include "re_tmr.h"
#include "ice/ice.h"

#include "rtpp_command_args.h"

#define A2PL(a, i) S2PL(&(a)->v[i])
//#define A2PL(a, i) S2PL((a)->v + i)
#define S2PL(sp) (struct pl){.p=(sp)->s, .l=(sp)->len}

static enum ice_transp transp_resolve(const struct pl *transp)
{
        if (!pl_strcasecmp(transp, "UDP"))
                return ICE_TRANSP_UDP;

        return ICE_TRANSP_NONE;
}

int
rtpp_cand_decode(struct icem *icem, const struct rtpp_command_argsp *args)
{
    static const char rel_addr_str[] = "raddr";
    static const char rel_port_str[] = "rport";
	struct pl foundation, compid, transp, prio, addr, port, cand_type;
	struct sa caddr, rel_addr;
	char type[8];
	uint8_t cid;
	int err;

	sa_init(&rel_addr, AF_INET);

	if (args->c < 8 || pl_strcasecmp(&A2PL(args, 6), "typ") != 0)
		return EINVAL;

    foundation = A2PL(args, 0);
    compid = A2PL(args, 1);
    transp = A2PL(args, 2);
    prio = A2PL(args, 3);
    addr = A2PL(args, 4);
    port = A2PL(args, 5);
    cand_type = A2PL(args, 7);
    struct rtpp_command_argsp extra = {.c = args->c - 8, .v = args->v + 8};

	if (ICE_TRANSP_NONE == transp_resolve(&transp)) {
		DEBUG_NOTICE("<%s> ignoring candidate with"
			     " unknown transport=%r (%r:%r)\n",
			     icem->name, &transp, &cand_type, &addr);
		return EINVAL;
	}

    /* Loop through " SP attr SP value" pairs */
    while (extra.c >= 2) {
        struct pl name, value;
        name = A2PL(&extra, 0);
        value = A2PL(&extra, 1);
        extra.c -= 2;
        extra.v += 2;

        if (0 == pl_strcasecmp(&name, rel_addr_str)) {
            err = sa_set(&rel_addr, &value,
                        sa_port(&rel_addr));
            if (err)
                return (err);
        }
        else if (0 == pl_strcasecmp(&name, rel_port_str)) {
            sa_set_port(&rel_addr, pl_u32(&value));
        }
    }

	err = sa_set(&caddr, &addr, pl_u32(&port));
	if (err)
		return err;

	cid = pl_u32(&compid);

	/* add only if not exist */
	if (icem_cand_find(&icem->rcandl, cid, &caddr))
		return 0;

	(void)pl_strcpy(&cand_type, type, sizeof(type));

	return icem_rcand_add(icem, ice_cand_name2type(type), cid,
			      pl_u32(&prio), &caddr, &rel_addr, &foundation);
}