#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"
#include "g729_compat.h"

#ifdef ENABLE_G729
# ifdef ENABLE_BCG729
int16_t *
g279_compat_decode(G729_DCTX *ctx, uint8_t *ibuf, size_t ibsize)
{
    static int16_t obuf[80];

    assert(ibsize <= 10);

#  if defined(HAVE_NEW_BCG729_API)
    bcg729Decoder(ctx, ibuf, ibsize, 0 /*no erasure*/, 0 /*not SID*/, 0 /*not RFC3389*/, obuf);
#  else
    bcg729Decoder(ctx, ibuf, 0, obuf);
#  endif

    return (obuf);
}

void
g279_compat_encode(G729_ECTX *ctx, int16_t ibuf[], uint8_t obuf[], uint8_t *bl)
{

#  if defined(HAVE_NEW_BCG729_API)
    bcg729Encoder(ctx, ibuf, obuf, bl);
#  else
    bcg729Encoder(ctx, ibuf, obuf);
    *bl = 10;
#  endif
}
# else
void
g279_compat_encode(G729_ECTX *ctx, int16_t ibuf[], uint8_t obuf[], uint8_t *bl)
{

    g729_encode_frame(ctx, ibuf, obuf);
    *bl = 10;
}
# endif
#endif
