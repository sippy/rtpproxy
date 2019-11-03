struct packet_observer_if;

DEFINE_METHOD(packet_observer_if, po_taste, void);
DEFINE_METHOD(packet_observer_if, po_enqueue, void);
DEFINE_METHOD(packet_observer_if, po_control, void);

struct packet_observer_if {
    po_taste_t taste;
    po_enqueue_t enqueue;
    po_control_t control;
};
