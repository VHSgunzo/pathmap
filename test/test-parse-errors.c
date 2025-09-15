#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pathmap_common.h"

static void test_missing_colon_returns_error_buf(void)
{
    char **linear = NULL;
    char *buffer = NULL;
    int pairs_len = 0;
    int rc = pm_parse_path_mapping_env("/from-only" , &linear, &pairs_len, &buffer);
    assert(rc != 0);
    assert(linear == NULL);
    assert(pairs_len == 0);
    assert(buffer == NULL);
}

static void test_even_pairs_ok(void)
{
    char **linear = NULL;
    char *buffer = NULL;
    int pairs_len = 0;
    int rc = pm_parse_path_mapping_env("/a:/b,/c:/d" , &linear, &pairs_len, &buffer);
    assert(rc == 0);
    assert(pairs_len == 2);
    assert(linear != NULL);
    free(linear);
    free(buffer);
}

int main(void)
{
    test_missing_colon_returns_error_buf();
    test_even_pairs_ok();
    printf("test-parse-errors: OK\n");
    return 0;
}


