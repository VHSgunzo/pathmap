#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
#ifdef STATX_SIZE
    struct statx stx;
    if (statx(AT_FDCWD, argv[1], 0, STATX_SIZE, &stx) == 0) {
        printf("%lld\n", (long long)stx.stx_size);
        return 0;
    }
    perror("statx");
    return 1;
#else
    fprintf(stderr, "statx not supported on this system\n");
    return 77; // skip
#endif
}

