struct rtpp_catch_dtmf;
struct po_manager;
struct rtpp_log;

DEFINE_METHOD(rtpp_catch_dtmf, rtpp_catch_dtmf_shutdown, void);

struct rtpp_catch_dtmf {
    struct rtpp_refcnt *rcnt;
    rtpp_catch_dtmf_shutdown_t shutdown;
};

struct rtpp_catch_dtmf *rtpp_catch_dtmf_ctor(struct rtpp_log *, struct po_manager *);
