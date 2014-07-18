#define DEFINE_METHOD(class, func, rval, args...) typedef rval (*func##_t)(struct class *, ## args)

struct rtpp_pcache_obj;
struct rtpp_pcache_fd;

DEFINE_METHOD(rtpp_pcache_obj, rtpp_pcache_obj_dtor, void);
DEFINE_METHOD(rtpp_pcache_obj, rtpp_pcache_obj_open, struct rtpp_pcache_fd *, const char *);
DEFINE_METHOD(rtpp_pcache_obj, rtpp_pcache_obj_read, int, struct rtpp_pcache_fd *, void *, size_t);
DEFINE_METHOD(rtpp_pcache_obj, rtpp_pcache_obj_close, void, struct rtpp_pcache_fd *);

struct rtpp_pcache_obj_priv;

struct rtpp_pcache_obj
{
    rtpp_pcache_obj_open_t open;
    rtpp_pcache_obj_read_t read;
    rtpp_pcache_obj_close_t close;
    rtpp_pcache_obj_dtor_t dtor;
    struct rtpp_pcache_obj_priv *pvt;
};

struct rtpp_pcache_obj *rtpp_pcache_ctor(void);
