/* -fopt-info-vec-all-internals */
/* -fopt-info-vec-missed */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_mallocs.h"
#include "rtpp_refcnt.h"
#include "rtpp_multilinear.h"

#define RANDLEN 64
#define RANDALIGN 128
#define RANDALIGN_MASK (~(uintptr_t)(RANDALIGN - 1))
#define HM_CHUNKS 8

static_assert((RANDLEN % HM_CHUNKS) == 0, "RANDLEN should be multiple of HM_CHUNKS");

typedef uint64_t al_uint64_t __attribute__((aligned(RANDALIGN)));

struct rtpp_multilinear_priv {
    struct rtpp_multilinear pub;
    const al_uint64_t *randomsource;
    uint64_t randomstor[0];
};

static uint32_t rtpp_multilinear_hash(struct rtpp_multilinear *, const char *, size_t);

static const struct rtpp_multilinear_smethods _rtpp_multilinear_smethods = {
    .hash = &rtpp_multilinear_hash,
};
const struct rtpp_multilinear_smethods * const rtpp_multilinear_smethods = &_rtpp_multilinear_smethods;

struct rnd {
    int rlen;
    const al_uint64_t *randomsource;
 };

static const uint64_t *
getnextrandom(const struct rnd *rnd, const uint64_t *crp, int step)
{
    return ((crp == &rnd->randomsource[rnd->rlen - 1]) ? rnd->randomsource : crp + step);
}

static uint32_t
hashMultilinear(const struct rnd *rnd, const char *string, const size_t length) {
    uint32_t op[HM_CHUNKS] = {};
    uint64_t psum[HM_CHUNKS] = {};
    uint64_t rbuf[HM_CHUNKS];
    ssize_t i;

    const uint64_t *randomsource = rnd->randomsource;

    for (i = length; i >= sizeof(op); string+=sizeof(op),i-=sizeof(op) ) {
        uint64_t rbuf[HM_CHUNKS];
        memcpy(rbuf, randomsource, sizeof(rbuf));
        memcpy(&op[0], string, sizeof(op));
        for (int j = 0; j < HM_CHUNKS; j++) {
            psum[j] += rbuf[j] * (uint64_t)(op[j]);
        }
        randomsource = getnextrandom(rnd, randomsource, HM_CHUNKS);
    }
    if (i > 0) {
        memcpy(&op[0], string, i);
        memset(((char *)&op[0]) + i, '\0', sizeof(op) - i);
        memcpy(rbuf, randomsource, sizeof(rbuf));
        for (int j = 0; j < HM_CHUNKS; j++) {
            psum[j] += rbuf[j] * (uint64_t)(op[j]);
        }
        randomsource = getnextrandom(rnd, randomsource, HM_CHUNKS);
    }
    uint64_t sum = *randomsource * (uint64_t)length;
    sum += *getnextrandom(rnd, randomsource, 1);
    for (int j = 0; j < HM_CHUNKS; j++)
        sum += psum[j];
    return (uint32_t) (sum >> 32);
}

struct rtpp_multilinear *
rtpp_multilinear_ctor(void)
{
    struct rtpp_multilinear_priv *pvt;
    size_t allocsize;
    uint64_t *randomsource;

    allocsize = sizeof(struct rtpp_multilinear_priv);
    allocsize += (RANDLEN * sizeof(pvt->randomsource[0])) + RANDALIGN;
    pvt = rtpp_rzmalloc(allocsize, PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    randomsource = (uint64_t *)((uintptr_t)&pvt->randomstor[0] & RANDALIGN_MASK);
    while (randomsource < pvt->randomstor)
        randomsource = (uint64_t *)((char *)randomsource + RANDALIGN);
    for (int i = 0; i < RANDLEN; i++) {
        randomsource[i] = (uint64_t)random() | ((uint64_t)random() << 32);
    }
    pvt->randomsource = randomsource;
#if defined(RTPP_DEBUG)
    pvt->pub.smethods = rtpp_multilinear_smethods;
#endif
    CALL_SMETHOD(pvt->pub.rcnt, use_stdfree, pvt);
    return ((&pvt->pub));

e0:
    return (NULL);
}

static uint32_t
rtpp_multilinear_hash(struct rtpp_multilinear *pub, const char *s, size_t len)
{
    struct rtpp_multilinear_priv *pvt;

    PUB2PVT(pub, pvt);
    const struct rnd rnd = {.rlen = RANDLEN, .randomsource = pvt->randomsource};
    return hashMultilinear(&rnd, s, len);
}

#if 1
#include <stdio.h>

int main(int argc, char **argv)
{
    uint32_t hash;
    struct rtpp_multilinear *rm = rtpp_multilinear_ctor();
    if (rm == NULL)
        return -1;
    hash = CALL_SMETHOD(rm, hash, argv[1], strlen(argv[1]));
    printf("%X\n", hash);
    return 0;
}
#endif
