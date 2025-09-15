#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pathmap_common.h"

void test_path_prefix_matches() {
    assert(pm_path_prefix_matches("/example/dir/", "/example/dir/") != 0);
    assert(pm_path_prefix_matches("/example/dir/", "/example/dir") != 0);
    assert(pm_path_prefix_matches("/example/dir", "/example/dir") != 0);
    assert(pm_path_prefix_matches("/example/dir", "/example/dir/") != 0);

    assert(pm_path_prefix_matches("/example/dir", "/example/dirt") == 0);
    assert(pm_path_prefix_matches("/example/dir", "/example/dirty") == 0);
    assert(pm_path_prefix_matches("/example/dir", "/example/dirty/") == 0);
    assert(pm_path_prefix_matches("/example/dir", "/example/dirty/file") == 0);

    assert(pm_path_prefix_matches("/", "/") != 0);
    assert(pm_path_prefix_matches("/", "/e") != 0);
    assert(pm_path_prefix_matches("/", "/example") != 0);
    assert(pm_path_prefix_matches("/e", "/e") != 0);
    assert(pm_path_prefix_matches("/e", "/e") != 0);

    assert(pm_path_prefix_matches("/e", "/example") == 0);
}

int main() {
    test_path_prefix_matches();
    return 0;
}
