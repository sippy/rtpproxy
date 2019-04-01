/*
 * Copyright (c) 2018 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "config_pp.h"

#include "rtpp_cfg_stable.h"
#include "rtpp_types.h"
#include "rtpp_cfile.h"
#include "rtpp_list.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"
#include "rtpp_module_if.h"
#include "rtpp_refcnt.h"
#include "rtpp_ucl.h"

#include "ucl.h"

static int parse_modules(struct rtpp_cfg_stable *, const ucl_object_t *);
static bool conf_helper_mapper(struct rtpp_log *, const ucl_object_t *,
  const conf_helper_map *, void *, const conf_helper_map **);

static char *
rtpp_module_dsop_canonic(const char *mname, char *buf, size_t blen)
{
     const char *dbug;

#if defined(RTPP_DEBUG)
     dbug = "_debug";
#else
     dbug = "";
#endif

     snprintf(buf, blen, "%s/rtpp_%s%s.so", MDDIR_PATH, mname, dbug);
     return (buf);
}

int
rtpp_cfile_process(struct rtpp_cfg_stable *csp)
{
    struct ucl_parser *parser;
    ucl_object_t *conf_root;
    ucl_object_iter_t it_conf;
    const ucl_object_t *obj_file;
    const char *cf_key;
    int fd, ecode;

    ecode = 0;

    fd = open(csp->cfile, O_RDONLY);
    if (fd < 0) {
        RTPP_ELOG(csp->glog, RTPP_LOG_ERR, "open failed: %s", csp->cfile);
        ecode = -1;
        goto e0;
    }

    parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    if (parser == NULL) {
        RTPP_LOG(csp->glog, RTPP_LOG_ERR, "ucl_parser_new() failed");
        ecode = -1;
        goto e1;
    }

    ucl_parser_add_fd(parser, fd);
    conf_root = ucl_parser_get_object(parser);
    if (conf_root == NULL) {
        RTPP_LOG(csp->glog, RTPP_LOG_ERR, "ucl_parser_get_object() failed");
        ecode = -1;
        goto e2;
    }
    if (ucl_parser_get_error(parser)) {
        RTPP_LOG(csp->glog, RTPP_LOG_ERR, "Parse Error occured: %s", ucl_parser_get_error(parser));
        ecode = -1;
        goto e3;
    }

    it_conf = ucl_object_iterate_new(conf_root);
    if (it_conf == NULL) {
        RTPP_LOG(csp->glog, RTPP_LOG_ERR, "ucl_object_iterate_new() failed");
        ecode = -1;
        goto e3;
    }
    while ((obj_file = ucl_object_iterate_safe(it_conf, true)) != NULL) {
        cf_key = ucl_object_key(obj_file);
        RTPP_LOG(csp->glog, RTPP_LOG_DBUG, "Entry: %s", cf_key);
        if (strcasecmp(cf_key, "modules") == 0) {
            if (parse_modules(csp, obj_file) < 0) {
                RTPP_LOG(csp->glog, RTPP_LOG_ERR, "parse_modules() failed");
                ecode = -1;
                goto e4;
            }
        }
    }
    if (ucl_object_iter_chk_excpn(it_conf)) {
        ecode = -1;
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
    return (ecode);
}

static const conf_helper_map default_module_map[] = {
    { "load", NULL }, /* The "load" is default */
    { NULL, (conf_helper_func) rtpp_ucl_set_unknown }
};

static int
parse_modules(struct rtpp_cfg_stable *csp, const ucl_object_t *wop)
{
    ucl_object_iter_t it_conf;
    const ucl_object_t *obj_file;
    const char *cf_key;
    const ucl_object_t *obj_key;
    int ecode, success;
    void *confp;
    const conf_helper_map *fent, *map;
    struct rtpp_module_conf *mcp;
    char mpath[PATH_MAX + 1];
    const char *cp, *mp;
    struct rtpp_module_if *mif;

    it_conf = ucl_object_iterate_new(wop);
    if (it_conf == NULL)
        return (-1);
    ecode = 0;
    while ((obj_file = ucl_object_iterate_safe(it_conf, true)) != NULL) {
        cf_key = ucl_object_key(obj_file);
        RTPP_LOG(csp->glog, RTPP_LOG_DBUG, "\tmodule: %s", cf_key);
        obj_key = ucl_object_find_key(obj_file, "load");
        if (obj_key == NULL) {
            cp = rtpp_module_dsop_canonic(cf_key, mpath, sizeof(mpath));
            if (cp == NULL) {
                RTPP_LOG(csp->glog, RTPP_LOG_ERR, "Error: Unable to find load parameter in module: %s", cf_key);
                ecode = -1;
                goto e0;
            }
        } else {
            if (obj_key->type != UCL_STRING) {
                RTPP_LOG(csp->glog, RTPP_LOG_ERR, "Error: \"load\" parameter in %s has a wrong type, string is expected", cf_key);
                ecode = -1;
                goto e0;
            }
            mp = ucl_object_tostring(obj_key);
            cp = realpath(mp, mpath);
            if (cp == NULL) {
                RTPP_ELOG(csp->glog, RTPP_LOG_ERR, "realpath() failed: %s", mp);
                ecode = -1;
                goto e0;
            }
        }
        mif = rtpp_module_if_ctor(cp);
        if (mif == NULL) {
            RTPP_LOG(csp->glog, RTPP_LOG_ERR, "dymanic module constructor has failed: %s", cp);
            ecode = -1;
            goto e0;
        }
        if (CALL_METHOD(mif, load, csp, csp->glog) != 0) {
            RTPP_LOG(csp->glog, RTPP_LOG_ERR, "%p->load() method has failed: %s", mif, cp);
            goto e1;
        }
        if (CALL_METHOD(mif, get_mconf, &mcp) < 0) {
            RTPP_LOG(csp->glog, RTPP_LOG_ERR, "%p->get_mconf() method has failed: %s", mif, cp);
            goto e1;
        }
        fent = NULL;
        if (mcp != NULL) {
            map = mcp->conf_map;
            confp = mcp->conf_data;
        } else {
            map = default_module_map;
            confp = NULL;
        }
        success = conf_helper_mapper(csp->glog, obj_file, map, confp, &fent);
        if (!success) {
            RTPP_LOG(csp->glog, RTPP_LOG_ERR, "Config parsing issue in section %s",
              cf_key);
            if (fent != NULL && fent->conf_key != NULL) {
                RTPP_LOG(csp->glog, RTPP_LOG_ERR, "\tparameter %s", fent->conf_key);
            }
            goto e1;
        }
        if (CALL_METHOD(mif, config) < 0) {
            RTPP_LOG(csp->glog, RTPP_LOG_ERR, "%p->config() method has failed: %s", mif, cp);
            goto e1;
        }
        rtpp_list_append(csp->modules_cf, mif);
        continue;
e1:
        ecode = -1;
        CALL_SMETHOD(mif->rcnt, decref);
        goto e0;
    }
e0:
    if (ucl_object_iter_chk_excpn(it_conf)) {
        RTPP_LOG(csp->glog, RTPP_LOG_ERR, "UCL has failed with an internal error");
        ecode = -1;
    }
    ucl_object_iterate_free(it_conf);
    return (ecode);
}

static bool
conf_helper_mapper(struct rtpp_log *log, const ucl_object_t *obj, const conf_helper_map *map,
  void *target, const conf_helper_map **fentrpp)
{
    ucl_object_iter_t it;
    const ucl_object_t *cur;
    const char *key = NULL;
    int i;
    bool ret = true, found = false;

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
                ret = map[i].callback(log, obj, cur, target);
                if (!ret && fentrpp != NULL)
                    *fentrpp = &map[i];
            }
            break;
        }
        if (!found && map[i].callback != NULL) {
            /* Call default handler if there is one */
            ret = map[i].callback(log, obj, cur, target);
            if (!ret && fentrpp != NULL)
                *fentrpp = &map[i];
        }
    }
    if (cur == NULL && ucl_object_iter_chk_excpn(it))
        ret = false;
    ucl_object_iterate_free(it);
    return (ret);
}
