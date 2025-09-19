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
#include <string.h>
#include <stdio.h>
#include "pathmap_common.h"

static void setup_mapping(struct pm_mapping_config *cfg, const char *from, const char *to)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->mappings[0][0] = from;
    cfg->mappings[0][1] = to;
    cfg->mapping_is_malloced[0] = 0;
    cfg->mapping_is_glob[0] = (strpbrk(from, "*?[") != NULL);
    cfg->mapping_count = 1;
}

int main(void)
{
    struct pm_mapping_config cfg;
    char out[4096];

    // Single-star tail capture
    setup_mapping(&cfg, "/usr/share/locale/*", "/tmp/AppDir/usr/share/locale/*");
    const char *m1 = pm_apply_mapping_with_config("/usr/share/locale/af/LC_MESSAGES/bleachbit.mo", out, sizeof out, &cfg);
    assert(strcmp(m1, "/tmp/AppDir/usr/share/locale/af/LC_MESSAGES/bleachbit.mo") == 0);

    // Multi-star capture in middle
    setup_mapping(&cfg, "/usr/share/locale/*/*/bleachbit.mo", "/tmp/AppDir/usr/share/locale/*/*/bleachbit.mo");
    const char *m2 = pm_apply_mapping_with_config("/usr/share/locale/af/LC_MESSAGES/bleachbit.mo", out, sizeof out, &cfg);
    assert(strcmp(m2, "/tmp/AppDir/usr/share/locale/af/LC_MESSAGES/bleachbit.mo") == 0);

    // Reverse glob mapping by TO pattern capture
    const char *r1 = pm_apply_reverse_mapping_with_config("/tmp/AppDir/usr/share/locale/af/LC_MESSAGES/bleachbit.mo", out, sizeof out, &cfg);
    assert(strcmp(r1, "/usr/share/locale/af/LC_MESSAGES/bleachbit.mo") == 0);

    // Exclude glob matching
    memset(&cfg, 0, sizeof(cfg));
    cfg.exclude_count = 3;
    cfg.excludes[0] = "/proc/*/*"; cfg.exclude_is_glob[0] = 1; // FNM_PATHNAME: '*' won't cross '/'
    cfg.excludes[1] = "/sys";    cfg.exclude_is_glob[1] = 0;
    cfg.excludes[2] = "/sys/*";  cfg.exclude_is_glob[2] = 1;
    assert(pm_is_excluded_prefix("/proc/self/cwd", &cfg) == 1);
    assert(pm_is_excluded_prefix("/sys", &cfg) == 1);
    assert(pm_is_excluded_prefix("/sys/kernel", &cfg) == 1);
    assert(pm_is_excluded_prefix("/home", &cfg) == 0);

    printf("test-glob: OK\n");
    return 0;
}
