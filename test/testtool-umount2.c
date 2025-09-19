#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target>\n", argv[0]);
        return 2;
    }
    const char *t = argv[1];
    if (umount2(t, 0) == -1) {
        // Print errno for visibility, but success isn't expected
        printf("errno:%d\n", errno);
        return 0;
    }
    puts("ok");
    return 0;
}

