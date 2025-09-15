#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pathmap_common.h"

static void test_normalize(void)
{
    char buf[4096];

    strcpy(buf, "/.////etc/ld.so.cache");
    pm_normalize_path_inplace(buf);
    assert(strcmp(buf, "/etc/ld.so.cache") == 0);

    strcpy(buf, "usr//../bin/./bash");
    pm_normalize_path_inplace(buf);
    assert(strcmp(buf, "/bin/bash") == 0);

    strcpy(buf, "/a/b/../../c");
    pm_normalize_path_inplace(buf);
    assert(strcmp(buf, "/c") == 0);
}

static void test_apply_mapping(void)
{
    const char *pairs[][2] = {
        { "/etc", "/tmp/etc" },
    };
    char out[4096];

    const char *r1 = pm_apply_mapping_pairs("/etc/ld.so.cache", pairs, 1, out, sizeof out);
    assert(strcmp(r1, "/tmp/etc/ld.so.cache") == 0);

    const char *r2 = pm_apply_mapping_pairs("/var/log", pairs, 1, out, sizeof out);
    assert(strcmp(r2, "/var/log") == 0);
}

int main(void)
{
    test_normalize();
    test_apply_mapping();
    printf("test-common: OK\n");
    return 0;
}


