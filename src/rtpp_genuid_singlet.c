#include <stdlib.h>
#include <stdint.h>

#include <rtpp_types.h>
#include <rtpp_genuid.h>

static struct rtpp_genuid_obj *gup = NULL;

void
rtpp_gen_uid_init(void)
{

    gup = rtpp_genuid_ctor();
}

void
rtpp_gen_uid(uint64_t *uip)
{

    CALL_METHOD(gup, gen, uip);
}
