#if defined(RTPP_DEBUG)
#include <assert.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_pcache.h"
#include "rtpp_mallocs.h"

struct rtpp_pcache_priv {
  struct rtpp_pcache *real;
  struct rtpp_hash_table *hash_table;
};

struct rtpp_pcache_full {
  struct rtpp_pcache pub;
  struct rtpp_pcache_priv pvt;
};

struct rtpp_pcache_fd {
  off_t cpos;
  struct rtpp_hash_table_entry *hte;
};

static void rtpp_pcache_dtor(struct rtpp_pcache *);
static struct rtpp_pcache_fd *rtpp_pcache_open(struct rtpp_pcache *, const char *);
static int rtpp_pcache_read(struct rtpp_pcache *, struct rtpp_pcache_fd *, void *, size_t);
static void rtpp_pcache_close(struct rtpp_pcache *, struct rtpp_pcache_fd *);

struct rtpp_pcache *
rtpp_pcache_ctor(void)
{
    struct rtpp_pcache_full *fp;
    struct rtpp_pcache *pub;
    struct rtpp_pcache_priv *pvt;

    fp = rtpp_zmalloc(sizeof(struct rtpp_pcache_full));
    if (fp == NULL) {
        return (NULL);
    }
    pub = &(fp->pub);
    pvt = &(fp->pvt);
    pvt->hash_table = rtpp_hash_table_ctor(rtpp_ht_key_str_t, 0);
    if (pvt->hash_table == NULL) {
        free(fp);
        return (NULL);
    }
    pub->pvt = pvt;
    pub->open = &rtpp_pcache_open;
    pub->read = &rtpp_pcache_read;
    pub->close = &rtpp_pcache_close;
    pub->dtor = &rtpp_pcache_dtor;
#if defined(RTPP_DEBUG)
    assert((void *)fp == (void *)pub);
#endif
    return (pub);
}

struct rtpp_pcache_fd *
rtpp_pcache_open(struct rtpp_pcache *self, const char *fname)
{
    struct rtpp_pcache_fd *p_fd;
    struct rtpp_pcache_priv *pvt;

    p_fd = rtpp_zmalloc(sizeof(struct rtpp_pcache_fd));
    if (p_fd == NULL) {
        return (NULL);
    }
    pvt = self->pvt;
    p_fd->hte = CALL_METHOD(pvt->hash_table, append, fname, p_fd);    
    return (p_fd);
}

static void
rtpp_pcache_close(struct rtpp_pcache *self, struct rtpp_pcache_fd *p_fd)
{

    CALL_METHOD(self->pvt->hash_table, remove_nc, p_fd->hte);
    free(p_fd);
}

static int
rtpp_pcache_read(struct rtpp_pcache *self, struct rtpp_pcache_fd *p_fd, void *buf, size_t len)
{

    p_fd->cpos += len;
    memset(buf, p_fd->cpos, len);
    return(len);
}

static void
rtpp_pcache_dtor(struct rtpp_pcache *self)
{

    free(self);
}
