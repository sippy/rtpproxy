/* Copyright (c) 2014, 2015 Allan Jude <allanjude@FreeBSD.org>. */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "ucl.h"

#include "hepconnector.h"

#include "rtpp_memdeb_internal.h"
#include "rtpp_types.h"
#include "rtpp_log_obj.h"
#include "rtpp_ucl.h"
#include "libexecinfo/stacktraverse.h"
#include "libexecinfo/execinfo.h"

RTPP_MEMDEB_STATIC(rtpproxy);
RTPP_MEMDEB_STATIC(libucl_test);

static bool conf_helper_mapper(const ucl_object_t *obj,
  conf_helper_map *map, void *target, conf_helper_map **failed);

extern struct rtpp_module_conf *rtpp_arh_conf;

static void
rtpp_log_obj_write_early(struct rtpp_log *self, const char *fname, int level,
  const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", fname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    return;
}

static void
rtpp_log_obj_ewrite_early(struct rtpp_log *self, const char *fname, int level,
  const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", fname);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    fflush(stderr);
    return;
}

static int
parse_modules(const ucl_object_t *wop)
{
    ucl_object_iter_t it_conf;
    const ucl_object_t *obj_file;
    const char *cf_key;
    const ucl_object_t *obj_key;
    int ecode, success;
    void *confp;
    conf_helper_map *map = rtpp_arh_conf->conf_map;
    conf_helper_map *fent;
    struct hep_ctx cbuf;

    it_conf = ucl_object_iterate_new(wop);
    if (it_conf == NULL)
        return (-1);
    ecode = 0;
    memset(&cbuf, '\0', sizeof(cbuf));
    confp = &cbuf;
    while ((obj_file = ucl_object_iterate_safe(it_conf, true)) != NULL) {
        cf_key = ucl_object_key(obj_file);
        printf("\tmodule: %s\n", cf_key);
        obj_key = ucl_object_find_key(obj_file, "load");
        if (obj_key == NULL) {
            fprintf(stderr, "Error: Unable to find load parameter in module: %s\n", cf_key);
            ecode = -1;
            goto e0;
        }
        fent = NULL;
        success = conf_helper_mapper(obj_file, map, confp, &fent);
        if (!success) {
            fprintf(stderr, "Config parsing issue in section %s",
              cf_key);
            if (fent != NULL && fent->conf_key != NULL) {
                fprintf(stderr, ", parameter %s", fent->conf_key);
            }
            fprintf(stderr, "\n");
            ecode = -1;
            goto e1;
        }
    }
e1:
    if (cbuf.capt_host != NULL) {
        free(cbuf.capt_host);
    }
e0:
    ucl_object_iterate_free(it_conf);
    return (ecode);
}

int
main(int argc, char **argv)
{
    int ecode;
    struct ucl_parser *parser;
    ucl_object_t *conf_root;
    ucl_object_iter_t it_conf;
    const ucl_object_t *obj_file;
    const char *cf_key;
    int fd;
    const char *cfile;

    RTPP_MEMDEB_INIT(rtpproxy);
    RTPP_MEMDEB_INIT1(libucl_test);

    ecode = 0;

    if (argc < 2) {
        cfile = "libucl_test.conf";
    } else if (argc == 2) {
        cfile = argv[1];
    } else {
        fprintf(stderr, "usage: libucl_test [conffile]\n");
        ecode = 1;
        goto e0;
    }
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
    if (it_conf == NULL) {
        fprintf(stderr, "ucl_object_iterate_new() failed\n");
        ecode = 1;
        goto e3;
    }
    while ((obj_file = ucl_object_iterate_safe(it_conf, true)) != NULL) {
        cf_key = ucl_object_key(obj_file);
        printf("Entry: %s\n", cf_key);
        if (strcasecmp(cf_key, "modules") == 0) {
            if (parse_modules(obj_file) < 0) {
                fprintf(stderr, "parse_modules() failed\n");
                ecode = 1;
                goto e4;
            }
        }
    }
e4:
    ucl_object_iterate_free(it_conf);
e3:
    ucl_object_unref(conf_root);
e2:
    ucl_parser_free(parser);
e1:
    close(fd);
e0:
    if ((rtpp_memdeb_dumpstats(_rtpproxy_memdeb, 0) != 0) || (rtpp_memdeb_dumpstats(_libucl_test_memdeb, 0) != 0))
        ecode = 1;

    return (ecode);
}

static bool
conf_helper_mapper(const ucl_object_t *obj, conf_helper_map *map,
  void *target, conf_helper_map **fentrpp)
{
    ucl_object_iter_t it;
    const ucl_object_t *cur;
    const char *key = NULL;
    int i;
    bool ret = true, found = false;
    static struct rtpp_log log = {.write = rtpp_log_obj_write_early, .ewrite = rtpp_log_obj_ewrite_early};

    it = ucl_object_iterate_new(obj);
    if (it == NULL)
        return (false);
    while ((cur = ucl_object_iterate_safe(it, true)) != NULL && ret) {
        key = ucl_object_key(cur);
        found = false;
        for (i = 0; map[i].conf_key; i++) {
            if (strcasecmp(map[i].conf_key, key) != 0)
                continue;
            found = true;
            if (map[i].callback != NULL) {
                ret = map[i].callback(&log, obj, cur, target);
                if (!ret && fentrpp != NULL)
                    *fentrpp = &map[i];
            }
            break;
        }
        if (!found && map[i].callback != NULL) {
            /* Call default handler if there is one */
            ret = map[i].callback(&log, obj, cur, target);
            if (!ret && fentrpp != NULL)
                *fentrpp = &map[i];
        }
    }
    ucl_object_iterate_free(it);
    return (ret);
}
