struct proto_cap {
    const char  *pc_id;
    const char  *pc_description;
};

struct rtpp_command;

void handle_ver_feature(struct cfg *cf, struct rtpp_command *cmd);
struct proto_cap *iterate_proto_caps(struct proto_cap *prevp);
