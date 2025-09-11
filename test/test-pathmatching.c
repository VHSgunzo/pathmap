#include <assert.h>
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