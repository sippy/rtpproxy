struct po_manager;
struct packet_observer_if;

DEFINE_METHOD(po_manager, po_manager_shutdown, void);
DEFINE_METHOD(po_manager, po_manager_reg, int, struct packet_observer_if *);

struct po_manager {
    struct rtpp_refcnt *rcnt;
    po_manager_reg_t reg;
    po_manager_shutdown_t shutdown;
};

struct po_manager *rtpp_po_mgr_ctor(void);
