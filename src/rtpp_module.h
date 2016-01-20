#define MODULE_API_REVISION 2

struct rtpp_cfg_stable;
struct rtpp_module_priv;
struct rtpp_accounting;

DEFINE_METHOD(rtpp_cfg_stable, rtpp_module_ctor, struct rtpp_module_priv *);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_dtor, void);
DEFINE_METHOD(rtpp_module_priv, rtpp_module_on_session_end, void,
  struct rtpp_accounting *);

struct api_version {
    int rev;
    size_t mi_size;
};

struct rtpp_minfo {
    const char *name;
    struct api_version ver;
    rtpp_module_ctor_t ctor;
    rtpp_module_dtor_t dtor;
    rtpp_module_on_session_end_t on_session_end;
};

#define MI_VER_INIT() {.rev = MODULE_API_REVISION, .mi_size = sizeof(struct rtpp_minfo)}
#define MI_VER_CHCK(sptr) ((sptr)->ver.rev == MODULE_API_REVISION && \
  (sptr)->ver.mi_size == sizeof(struct rtpp_minfo))
