#pragma once

#if defined(FUZZ_STANDALONE)
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#endif /* FUZZ_STANDALONE */

#if defined(FUZZ_STANDALONE)
extern int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((__weak__));

int LLVMFuzzerTestOneInput(const char *data, size_t size);

__attribute__((constructor)) static void
rtpp_init()
{
    if (LLVMFuzzerInitialize != NULL) {
        int r = LLVMFuzzerInitialize(NULL, NULL);
        if (r != 0)
            abort();
    }
}

int
main(int argc, char *argv[])
{
    int fflag, ch, fd;
    char buf[1024], *cp;
    size_t size;

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
#else
const char *__asan_default_options() {
  return "verbosity=0";
}
#endif /* FUZZ_STANDALONE */
