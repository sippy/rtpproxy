#if !defined(_FUZZ_STANDALONE_H)
#define _FUZZ_STANDALONE_H

#if defined(FUZZ_STANDALONE)
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#endif /* FUZZ_STANDALONE */

#if defined(__linux__)
static int optreset; /* Not present in linux */
#endif

static struct opt_save {
    char *optarg;
    int optind;
    int optopt;
    int opterr;
    int optreset;
} opt_save;

#define OPT_SAVE() (opt_save = (struct opt_save){optarg, optind, optopt, opterr, optreset})
#define OPT_RESTORE() ({ \
    optarg = opt_save.optarg; \
    optind = opt_save.optind; \
    optopt = opt_save.optopt; \
    opterr = opt_save.opterr; \
    optreset = opt_save.optreset; \
})

#if defined(FUZZ_STANDALONE)
int LLVMFuzzerTestOneInput(const char *data, size_t size);

int
main(int argc, char *argv[])
{
    int fflag, ch, fd;
    char buf[1024], *cp;
    size_t size;

    fflag = 0;
    OPT_SAVE();
    while ((ch = getopt(argc, argv, "f")) != -1) {
        switch (ch) {
        case 'f':
            fflag = 1;
            break;
        default:
            return (-1);
        }
    }
    argc -= optind;
    argv += optind;
    OPT_RESTORE();

    assert(argc == 1);
    if (fflag) {
        fd = open(argv[0], O_RDONLY, 0);
        assert(fd >= 0);
        size = read(fd, buf, sizeof(buf));
        assert(size > 0);
        cp = buf;
    } else {
        cp = argv[0];
        size = strlen(cp);
    }
    LLVMFuzzerTestOneInput(cp, size);
    return (0);
}
#endif /* FUZZ_STANDALONE */
#endif /* _FUZZ_STANDALONE_H */
