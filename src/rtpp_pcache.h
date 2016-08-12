struct rtpp_pcache;
struct rtpp_pcache_fd;

#if !defined(DEFINE_METHOD)
#error "rtpp_types.h" needs to be included
#endif

DEFINE_METHOD(rtpp_pcache, rtpp_pcache_dtor, void);
DEFINE_METHOD(rtpp_pcache, rtpp_pcache_open, struct rtpp_pcache_fd *, const char *);
DEFINE_METHOD(rtpp_pcache, rtpp_pcache_read, int, struct rtpp_pcache_fd *, void *, size_t);
DEFINE_METHOD(rtpp_pcache, rtpp_pcache_close, void, struct rtpp_pcache_fd *);

struct rtpp_pcache_priv;

struct rtpp_pcache
{
    rtpp_pcache_open_t open;
    rtpp_pcache_read_t read;
    rtpp_pcache_close_t close;
    rtpp_pcache_dtor_t dtor;
    struct rtpp_pcache_priv *pvt;
};

struct rtpp_pcache *rtpp_pcache_ctor(void);
