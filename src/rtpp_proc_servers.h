struct rtpp_cfg;
struct rtpp_anetio_cf;
struct rtpp_proc_servers;
struct rtpp_refcnt;
struct rtpp_server;

DEFINE_METHOD(rtpp_proc_servers, rtpp_proc_servers_reg, int,
  struct rtpp_server *, int);
DEFINE_METHOD(rtpp_proc_servers, rtpp_proc_servers_unreg, int, uint64_t);
DEFINE_METHOD(rtpp_proc_servers, rtpp_proc_servers_plr_start, int,
  uint64_t, double);

struct rtpp_proc_servers_smethods
{
    METHOD_ENTRY(rtpp_proc_servers_reg, reg);
    METHOD_ENTRY(rtpp_proc_servers_unreg, unreg);
    METHOD_ENTRY(rtpp_proc_servers_plr_start, plr_start);
};

struct rtpp_proc_servers {
    struct rtpp_refcnt *rcnt;
#if defined(RTPP_DEBUG)
    const struct rtpp_proc_servers_smethods * smethods;
#endif
};

struct rtpp_proc_servers *rtpp_proc_servers_ctor(const struct rtpp_cfg *,
  struct rtpp_anetio_cf *);
