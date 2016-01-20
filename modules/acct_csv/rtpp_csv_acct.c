#include <stdint.h>
#include <stdlib.h>

#include "rtpp_module.h"

#define MI_VER_INIT(sname) {.rev = MODULE_API_REVISION, .mi_size = sizeof(sname)}

struct moduleinfo rtpp_module = {
    .name = "csv_acct",
    .ver = MI_VER_INIT(struct moduleinfo)
};
