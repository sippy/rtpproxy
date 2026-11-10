/*
 * Fuzzer for rtpproxy configuration file processing.
 *
 * Feeds fuzzed bytes as a configuration file (UCL format) into
 * rtpp_cfile_process(), the entry point rtpproxy main() uses for -c config
 * files. This exercises:
 *   - src/rtpp_cfile.c: file reading, UCL parse orchestration, module
 *     section dispatch;
 *   - src/rtpp_ucl.c: rtpproxy's UCL helper wrappers and unknown-key
 *     handling;
 *   - external/libucl: the bundled UCL parser/emitter/schema/msgpack code,
 *     which no other fuzz target reaches (0% covered as of 2026-11-09);
 *   - module configuration loading: with a "load" parameter pointing at a
 *     module DSO the build ships next to the fuzzers (the build copies
 *     every module DSO from modules/MOD/.libs into $OUT), the harness
 *     drives rtpp_module_if_ctor() (dlopen), module load() and the
 *     per-module configuration key parsers (e.g. acct_rtcp_hep capt_* keys
 *     in rtpp_arh_conf.c).
 *
 * Threat model: the configuration file is the trust boundary for
 * librtpproxy API consumers and for anyone provisioning rtpproxy config;
 * UCL is a structured text format whose parser (here a bundled copy) is a
 * classic memory-safety target. Config-specified module "load" paths go
 * through realpath() + dlopen(): path handling on attacker-chosen strings
 * is in scope; DSOs that do not exist simply fail cleanly, and only DSOs
 * shipped by this same build can ever be loaded inside the OSS-Fuzz
 * environment.
 *
 * Known growth vector: each successfully loaded module instance stays
 * registered in the daemon config (by design); once the process runs out
 * of file descriptors the module socket setup fails cleanly and parsing
 * continues, so the fuzzer degrades to parser-only fuzzing instead of
 * crashing or hanging.
 */

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzz_standalone.h"
#include "rfz_utils.h"

#define HAVE_CONFIG_H 1
#include "config_pp.h"

#include "rtpp_cfg.h"
#include "rtpp_cfile.h"

static char cfgpath[PATH_MAX + 1];

int
LLVMFuzzerInitialize(int *_argc, char ***_argv)
{

    if (RTPPInitialize() != 0)
        return (-1);
    /*
     * Work in $OUT (falling back to /tmp) so that seed corpora using
     * relative "load" paths resolve next to the fuzzer binaries, where
     * the build ships the module DSOs.
     */
    const char *outp = getenv("OUT");
    if (outp != NULL && chdir(outp) != 0)
        chdir("/tmp");
    return (0);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    const char *saved_cfile;
    FILE *fp;

    if (size < 2 || size > 65536)
        return (0);

    snprintf(cfgpath, sizeof(cfgpath), "/tmp/rfz_cfg_%ld.ucl", (long)getpid());
    fp = fopen(cfgpath, "wb");
    assert(fp != NULL);
    assert(fwrite(data, 1, size, fp) == size);
    fclose(fp);

    saved_cfile = gconf.cfsp->cfile;
    gconf.cfsp->cfile = cfgpath;
    rtpp_cfile_process(gconf.cfsp);
    gconf.cfsp->cfile = saved_cfile;

    unlink(cfgpath);
    return (0);
}
