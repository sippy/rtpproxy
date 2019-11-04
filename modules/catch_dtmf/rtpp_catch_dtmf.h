struct rtpp_catch_dtmf;
struct po_manager;
struct rtpp_log;
struct rtpp_stream;
struct rtpp_command_args;

DEFINE_METHOD(rtpp_catch_dtmf, rtpp_catch_dtmf_command, int, struct rtpp_stream *,
  const struct rtpp_command_args *);

struct rtpp_catch_dtmf {
    struct rtpp_refcnt *rcnt;
    rtpp_catch_dtmf_command_t handle_command;
};

struct rtpp_catch_dtmf *rtpp_catch_dtmf_ctor(struct rtpp_log *, struct po_manager *);
