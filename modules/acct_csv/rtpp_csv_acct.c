#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct rtpp_module_priv {
   int foo;
   char *baz;
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
    bar.baz = module_strdup("hello, world!");
    return (&bar);
}

static void
rtpp_csv_acct_dtor(struct rtpp_module_priv *pvt)
{

    assert(pvt->foo == 123456);
    assert(strcmp(pvt->baz, "hello, world!") == 0);
    module_free(pvt->baz);
    return;
}
