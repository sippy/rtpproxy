#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "rtpp_types.h"
#include "rtpp_module.h"

struct rtpp_module_priv {
   int foo;
};

static struct rtpp_module_priv *rtpp_csv_acct_ctor(struct rtpp_cfg_stable *);
static void rtpp_csv_acct_dtor(struct rtpp_module_priv *);

struct rtpp_minfo rtpp_module = {
    .name = "csv_acct",
    .ver = MI_VER_INIT(),
    .ctor = rtpp_csv_acct_ctor,
    .dtor = rtpp_csv_acct_dtor
};

static struct rtpp_module_priv bar;

static struct rtpp_module_priv *
rtpp_csv_acct_ctor(struct rtpp_cfg_stable *cfsp)
{

    bar.foo = 123456;
    return (&bar);
}

static void
rtpp_csv_acct_dtor(struct rtpp_module_priv *pvt)
{

    assert(pvt->foo == 123456);
    return;
}
