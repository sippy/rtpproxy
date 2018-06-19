#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

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
    int fd;
    const char *cfile;

    RTPP_MEMDEB_INIT(rtpproxy);

    ecode = 0;

    cfile = "libucl_test.conf";
    fd = open(cfile, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(\"%s\") failed\n", cfile);
        ecode = 1;
        goto e0;
    }

    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    if (parser == NULL) {
        fprintf(stderr, "ucl_parser_new() failed\n");
        ecode = 1;
        goto e1;
    }

    ucl_parser_add_fd(parser, fd);
    conf_root = ucl_parser_get_object(parser);
    if (conf_root == NULL) {
        fprintf(stderr, "ucl_parser_get_object() failed\n");
        ecode = 1;
        goto e2;
    }
    if (ucl_parser_get_error(parser)) {
        fprintf(stderr, "Parse Error occured: %s\n", ucl_parser_get_error(parser));
        ecode = 1;
        goto e3;
    }

    it_conf = ucl_object_iterate_new(conf_root);
    ucl_object_iterate_free(it_conf);

e3:
    ucl_object_unref(conf_root);
e2:
    ucl_parser_free(parser);
e1:
    close(fd);
e0:
    ecode = rtpp_memdeb_dumpstats(_rtpproxy_memdeb, 0) == 0 ? ecode : 1;

    return (ecode);
}

