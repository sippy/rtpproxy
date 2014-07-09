struct rtpp_hash_table_obj;
struct rtpp_hash_table_entry;

DEFINE_METHOD(rtpp_hash_table_obj, hash_table_append, struct rtpp_hash_table_entry *, const char *, void *);
DEFINE_METHOD(rtpp_hash_table_obj, hash_table_remove, void, const char *key, struct rtpp_hash_table_entry *sp);
DEFINE_METHOD(rtpp_hash_table_obj, hash_table_remove_nc, void, struct rtpp_hash_table_entry *sp);
DEFINE_METHOD(rtpp_hash_table_obj, hash_table_findfirst, struct rtpp_hash_table_entry *,
  const char *key, void **);
DEFINE_METHOD(rtpp_hash_table_obj, hash_table_findnext,  struct rtpp_hash_table_entry *,
  struct rtpp_hash_table_entry *, void **);
DEFINE_METHOD(rtpp_hash_table_obj, hash_table_dtor, void);

struct rtpp_hash_table_priv;

struct rtpp_hash_table_obj
{
    hash_table_append_t append;
    hash_table_remove_t remove;
    hash_table_remove_nc_t remove_nc;
    hash_table_findfirst_t findfirst;
    hash_table_findnext_t findnext;
    hash_table_dtor_t dtor;
    struct rtpp_hash_table_priv *pvt;
};

struct rtpp_hash_table_obj *rtpp_hash_table_ctor(void);
