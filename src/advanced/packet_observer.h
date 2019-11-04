struct packet_observer_if;
struct rtp_packet;
struct rtpp_stream;

DEFINE_RAW_METHOD(po_taste, int, const struct rtpp_stream *,
  const struct rtp_packet *);
DEFINE_RAW_METHOD(po_enqueue, void, void *,
  const struct rtpp_stream *, const struct rtp_packet *);
DEFINE_RAW_METHOD(po_control, void);

struct packet_observer_if {
    void *arg;
    po_taste_t taste;
    po_enqueue_t enqueue;
    po_control_t control;
};
