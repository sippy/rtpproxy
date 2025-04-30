#pragma once

struct RTPPInitializeParams {
    const char *ttl;
    const char *setup_ttl;
    const char *socket;
    const char *debug_level;
    const char *notify_socket;
    const char *rec_spool_dir;
    const char *rec_final_dir;
    const char *modules[];
};

struct rtpp_conf {
    struct rtpp_cfg *cfsp;
    int tfd;
};

int RTPPInitialize(void);
void SeedRNGs(void);

extern struct rtpp_conf gconf;
extern struct RTPPInitializeParams RTPPInitializeParams;
