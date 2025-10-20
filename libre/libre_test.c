#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "re_types.h"
#include "re_fmt.h"
#include "re_list.h"
#include "re_tmr.h"
#include "re_sa.h"
#include "re_mem.h"
#include "re_mbuf.h"
#include "re_stun.h"
#include "re_ice.h"
#include "re_udp.h"
#include "ice/ice.h"

#ifdef RTPP_CHECK_LEAKS
#include "rtpp_memdeb_internal.h"
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"
#endif

#include "rtpp_command_args.h"

#include "rtpp_re.h"

#ifdef RTPP_CHECK_LEAKS
RTPP_MEMDEB_STATIC(libre);
RTPP_MEMDEB_STATIC(libre_test);
#endif

//typedef int udp_helper_send_h;
//typedef int udp_helper_recv_h;
struct udp_sock;
struct udp_helper;

void
re_dbg_printf(int level, const char *buf, int len)
{
    fprintf(stderr, "%.*s\n", len, buf);
}

int
udp_register_helper(struct udp_helper **uhp, struct udp_sock *us, int layer,
  udp_helper_send_h *sh, udp_helper_recv_h *rh, void *arg)
{
    printf("udp_register_helper(%p, %p, %d, %p, %p, %p)\n", uhp, us, layer, sh, rh, arg);
    return (0);
}

int
udp_local_get(const struct udp_sock *us, struct sa *local)
{
    /* Not implemented */
    abort();
}

#define S(sp) (rtpp_str_t){.s=sp, .len=sizeof(sp)-1}

int
main(int argc, char **argv)
{
    const struct rtpp_command_argsp testv[] = {
        {.v = (rtpp_str_t[]){S("2295360926"), S("1"), S("udp"), S("2122260223"), S("192.168.56.1"), S("52797"), S("typ"), S("host"), S("generation"), S("0"), S("network-id"), S("1")}, .c = 12},
        {.v = (rtpp_str_t[]){S("593947779"), S("1"), S("udp"), S("2122194687"), S("192.168.121.1"), S("52798"), S("typ"), S("host"), S("generation"), S("0"), S("network-id"), S("2")}, .c = 12},
        {.v = (rtpp_str_t[]){S("2515826778"), S("1"), S("udp"), S("2122129151"), S("192.168.23.190"), S("52799"), S("typ"), S("host"), S("generation"), S("0"), S("network-id"), S("3")}, .c = 12},
        {.v = (rtpp_str_t[]){S("4129263366"), S("1"), S("tcp"), S("1518280447"), S("192.168.56.1"), S("9"), S("typ"), S("host"), S("tcptype"), S("active"), S("generation"), S("0"), S("network-id"), S("1")}, .c = 14},
        {.v = (rtpp_str_t[]){S("1571360283"), S("1"), S("tcp"), S("1518214911"), S("192.168.121.1"), S("9"), S("typ"), S("host"), S("tcptype"), S("active"), S("generation"), S("0"), S("network-id"), S("2")}, .c = 14},
        {.v = (rtpp_str_t[]){S("3946552002"), S("1"), S("tcp"), S("1518149375"), S("192.168.23.190"), S("9"), S("typ"), S("host"), S("tcptype"), S("active"), S("generation"), S("0"), S("network-id"), S("3")}, .c = 14},
        {.v = (rtpp_str_t[]){S("1413099280"), S("1"), S("udp"), S("1685921535"), S("207.81.61.34"), S("52799"), S("typ"), S("srflx"), S("raddr"), S("192.168.23.190"), S("rport"), S("52799"), S("generation"), S("0"), S("network-id"), S("3")}, .c = 17},
        {0},
    };
    struct icem *icem; /*= {.lmode = ICE_MODE_LITE};*/
    struct icem_comp *comp; /*= {.icem = &icem};*/
    struct sa src = {0};
    struct stun_msg *req;
    int id = 10;
    int proto = -1;
    const char *lufrag = "foobar";
    const char *lpwd = "barfoobarfoobarfoobarfoo";
    uint64_t tiebrk = 1;
    struct ice_cand_attr cand;

#ifdef RTPP_CHECK_LEAKS
    RTPP_MEMDEB_INIT(libre);
    RTPP_MEMDEB_INIT1(libre_test);
#endif

    void *sock = mem_zalloc(1, NULL);
#if 0
    for (int i=0; testv[i] != NULL; i++) {
        int err = ice_cand_attr_decode(&cand, testv[i]);
        assert(err == 0);
    }
#endif
    assert(icem_alloc(&icem, ICE_MODE_LITE, ICE_ROLE_CONTROLLED, IPPROTO_UDP, 0,
      tiebrk, lufrag, lpwd, NULL, NULL) == 0);
    for (int i=0; testv[i].c != 0; i++) {
        const struct rtpp_command_argsp args = {.c=testv[i].c, .v=testv[i].v};
        int err = rtpp_cand_decode(icem, &args, NULL);
        assert(err == 0);
    }
    assert(icem_comp_alloc(&comp, icem, id, sock) == 0);
    mem_deref(comp);
    mem_deref(icem);
    mem_deref(sock);
#if 0
    icem_stund_recv(comp, &src, req, 0);
#endif
    int ecode = 0;
#ifdef RTPP_CHECK_LEAKS
    if ((rtpp_memdeb_dumpstats(_libre_memdeb, 0) != 0) || (rtpp_memdeb_dumpstats(_libre_test_memdeb, 0) != 0))
        ecode = 1;
#endif

    return (ecode);
}
