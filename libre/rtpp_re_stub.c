#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define ABSTRACT_FUNC_STUB(ret, func, ...) \
    ret __attribute__((weak)) func(__VA_ARGS__) { abort(); }

struct ice_candpair;
struct tcp_conn;
struct sa;
struct turnc;
typedef void turnc_chan_h;
struct tmr;
typedef void tmr_h;
typedef void udp_recv_h;
typedef void tcp_estab_h;
typedef void tcp_recv_h;
typedef void tcp_close_h;

ABSTRACT_FUNC_STUB(int, icem_conncheck_send, struct ice_candpair *cp, bool use_cand, bool trigged);
ABSTRACT_FUNC_STUB(int, tcp_send, struct tcp_conn *tc, struct mbuf *mb);
ABSTRACT_FUNC_STUB(int, udp_send, struct udp_sock *us, const struct sa *dst, struct mbuf *mb);
ABSTRACT_FUNC_STUB(int, turnc_add_chan, struct turnc *turnc, const struct sa *peer, turnc_chan_h *ch, void *arg);
ABSTRACT_FUNC_STUB(void, tmr_start, struct tmr *tmr, uint64_t delay, tmr_h *th, void *arg);
ABSTRACT_FUNC_STUB(int, stun_indication, int proto, void *sock, const struct sa *dst, size_t presz,
  uint16_t method, const uint8_t *key, size_t keylen, bool fp, uint32_t attrc, ...);
ABSTRACT_FUNC_STUB(uint8_t, ch_hex, char ch);
ABSTRACT_FUNC_STUB(int, udp_listen, struct udp_sock **usp, const struct sa *local,
  udp_recv_h *rh, void *arg);
ABSTRACT_FUNC_STUB(int, tcp_connect, struct tcp_conn **tcp, const struct sa *peer,
  tcp_estab_h *eh, tcp_recv_h *rh, tcp_close_h *ch, void *arg);
ABSTRACT_FUNC_STUB(uint64_t, tmr_get_expire, const struct tmr *tmr);
