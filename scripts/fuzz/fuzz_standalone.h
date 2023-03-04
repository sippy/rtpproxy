#if defined(FUZZ_STANDALONE) && !defined(_FUZZ_STANDALONE_H)
#define _FUZZ_STANDALONE_H

#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const char *data, size_t size);

int
main(int argc, char *argv[])
{
    int fflag, ch, fd;
    char buf[1024], *cp;
    size_t size;
    struct {
        char *optarg;
        int optind;
        int optopt;
        int opterr;
        int optreset;
    } opt_save = {optarg, optind, optopt, opterr, optreset};

    fflag = 0;
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

    optarg = opt_save.optarg;
    optind = opt_save.optind;
    optopt = opt_save.optopt;
    opterr = opt_save.opterr;
    optreset = opt_save.optreset;

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
#endif
