struct po_manager;
struct packet_observer_if;
struct rtpp_stream;
struct rtp_packet;

DEFINE_METHOD(po_manager, po_manager_reg, int, const struct packet_observer_if *);
DEFINE_METHOD(po_manager, po_manager_observe, void, struct rtpp_stream *,
  const struct rtp_packet *);

struct po_manager {
    struct rtpp_refcnt *rcnt;
    po_manager_reg_t reg;
    po_manager_observe_t observe;
};

struct po_manager *rtpp_po_mgr_ctor(void);
