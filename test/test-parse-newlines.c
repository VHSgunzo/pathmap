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
#include "pathmap_common.h"

int main(void)
{
    // Newlines and commas mixed, with spaces
    const char *env = "/a:/b,\n  /c:/d\r\n/e:/f,  /g:/h\n";
    char **linear = NULL; char *buf = NULL; int n = 0;
    int rc = pm_parse_path_mapping_env(env, &linear, &n, &buf);
    assert(rc == 0);
    assert(n == 4);
    assert(strcmp(linear[0], "/a") == 0);
    assert(strcmp(linear[1], "/b") == 0);
    assert(strcmp(linear[2], "/c") == 0);
    assert(strcmp(linear[3], "/d") == 0);
    assert(strcmp(linear[4], "/e") == 0);
    assert(strcmp(linear[5], "/f") == 0);
    assert(strcmp(linear[6], "/g") == 0);
    assert(strcmp(linear[7], "/h") == 0);
    free(linear); free(buf);

    // Invalid/empty entries skipped
    env = ",,,/x:/y, , /z: \n, /ok:/done";
    linear = NULL; buf = NULL; n = 0;
    rc = pm_parse_path_mapping_env(env, &linear, &n, &buf);
    assert(rc == 0);
    assert(n == 2);
    assert(strcmp(linear[0], "/x") == 0);
    assert(strcmp(linear[1], "/y") == 0);
    assert(strcmp(linear[2], "/ok") == 0);
    assert(strcmp(linear[3], "/done") == 0);
    free(linear); free(buf);

    printf("test-parse-newlines: OK\n");
    return 0;
}
