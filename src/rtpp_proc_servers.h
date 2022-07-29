struct rtpp_anetio_cf;

struct rtpp_proc_servers {
    struct rtpp_refcnt *rcnt;
};

struct rtpp_proc_servers *rtpp_proc_servers_ctor(const struct rtpp_cfg *,
  struct rtpp_anetio_cf *);
