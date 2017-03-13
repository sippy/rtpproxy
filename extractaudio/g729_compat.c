#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"
#include "g729_compat.h"

#ifdef ENABLE_BCG729
int16_t *
g279_compat_decode(G729_DCTX *ctx, uint8_t *ibuf, size_t ibsize)
{
    static int16_t obuf[80];

    assert(ibsize <= 10);

    bcg729Decoder(ctx, ibuf, ibsize, 0 /*no erasure*/, 0 /*not SID*/, 0 /*not RFC3389*/, obuf);

    return (obuf);
}
#endif
