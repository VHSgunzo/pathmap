#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    int ok1 = access(path, R_OK) == 0;
#ifdef AT_FDCWD
    int ok2 = faccessat(AT_FDCWD, path, R_OK, 0) == 0;
#else
    int ok2 = 1;
#endif
#ifdef SYS_faccessat2
    int ok3 = faccessat2(AT_FDCWD, path, R_OK, 0) == 0;
#else
    int ok3 = 1;
#endif
    if (ok1 && ok2 && ok3) {
        puts("yes");
        return 0;
    }
    puts("no");
    return 1;
}

