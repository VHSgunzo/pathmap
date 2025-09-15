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

static void test_update_argv0(void)
{
    const char *orig = "/virtual/bin/tool";
    const char *mapped = "/real/bin/tool";
    char *argv_in[] = { (char*)"/virtual/bin/tool", (char*)"arg1", NULL };
    char **argv_out = pm_update_argv0(orig, mapped, argv_in);
    assert(argv_out != NULL);
    assert(strcmp(argv_out[0], "/real/bin/tool") == 0);
    assert(strcmp(argv_out[1], "arg1") == 0);
    pm_free_argv0(argv_out, mapped);
}

int main(void)
{
    test_update_argv0();
    printf("test-argv0: OK\n");
    return 0;
}


