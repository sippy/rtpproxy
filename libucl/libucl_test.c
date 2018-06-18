#include <assert.h>

#include "ucl.h"

#include "rtpp_memdeb_internal.h"

RTPP_MEMDEB_STATIC(rtpproxy);

int
main(int argc, char **argv)
{
    int ecode;
    struct ucl_parser *parser;
    ucl_object_t *conf_root;
    ucl_object_iter_t it_conf;

    RTPP_MEMDEB_INIT(rtpproxy);
    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    conf_root = ucl_parser_get_object(parser);
    it_conf = ucl_object_iterate_new(conf_root);
    ucl_object_iterate_free(it_conf);
    ucl_parser_free(parser);
    ucl_object_unref(conf_root);

    ecode = rtpp_memdeb_dumpstats(_rtpproxy_memdeb, 0) == 0 ? 0 : 1;

    return (ecode);
}

