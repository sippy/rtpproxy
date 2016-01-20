#define MODULE_API_REVISION 1

struct api_version {
    int rev;
    size_t mi_size;
};

struct moduleinfo {
    const char *name;
    struct api_version ver;
};

#define MI_VER_INIT(sname) {.rev = MODULE_API_REVISION, .mi_size = sizeof(sname)}
