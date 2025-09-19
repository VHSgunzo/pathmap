#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    const char *p = argv[1];
    struct statfs sfs;
    if (statfs(p, &sfs) == 0) {
        printf("fs:%ld\n", (long)sfs.f_type);
    } else {
        perror("statfs");
        return 1;
    }
    struct statvfs svfs;
    if (statvfs(p, &svfs) == 0) {
        printf("bsize:%lu\n", (unsigned long)svfs.f_bsize);
    } else {
        perror("statvfs");
        return 1;
    }
    return 0;
}

