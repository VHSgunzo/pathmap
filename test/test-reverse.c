#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pathmap_common.h"

static void test_reverse_mapping_pairs(void)
{
    struct pm_mapping_config cfg;
    cfg.mapping_count = 0;
    cfg.mappings[cfg.mapping_count][0] = "/a";
    cfg.mappings[cfg.mapping_count][1] = "/b";
    cfg.mapping_is_malloced[cfg.mapping_count] = 0;
    cfg.mapping_count++;

    char out[4096];
    const char *r1 = pm_apply_reverse_mapping_with_config("/b/x", out, sizeof out, &cfg);
    assert(strcmp(r1, "/a/x") == 0);

    const char *r2 = pm_apply_reverse_mapping_with_config("/c/x", out, sizeof out, &cfg);
    assert(strcmp(r2, "/c/x") == 0);
}

int main(void)
{
    test_reverse_mapping_pairs();
    printf("test-reverse: OK\n");
    return 0;
}


