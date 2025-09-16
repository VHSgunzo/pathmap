#ifndef PATHMAP_COMMON_H
#define PATHMAP_COMMON_H

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// Default exclusions
static const char *pm_default_excludes[] = {
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
};
static const size_t pm_default_exclude_count = sizeof pm_default_excludes / sizeof pm_default_excludes[0];

// Default mappings when none provided
static const char *pm_default_mappings[][2] = {
    { "/tmp/path-mapping/tests/virtual", "/tmp/path-mapping/tests/real" },
};
static const size_t pm_default_mapping_count = sizeof pm_default_mappings / sizeof pm_default_mappings[0];

static inline size_t pm_pathlen(const char *path)
{
    size_t path_length = strlen(path);
    while (path_length > 0 && path[path_length - 1] == '/') {
        path_length -= 1;
    }
    return path_length;
}

static inline int pm_path_prefix_matches(const char *prefix, const char *path)
{
    size_t prefix_len = pm_pathlen(prefix);
    if (strncmp(prefix, path, prefix_len) == 0) {
        char after = path[prefix_len];
        return after == '/' || after == '\0';
    }
    return 0;
}

static inline void pm_normalize_path_inplace(char *path)
{
    char tmp[MAX_PATH];
    size_t len = strlen(path);
    size_t ti = 0;
    size_t seg_start = 0;
    if (path[0] != '/') tmp[ti++] = '/';
    for (size_t i = 0; i <= len; i++) {
        if (i == len || path[i] == '/') {
            size_t seg_len = i - seg_start;
            if (seg_len == 0) {
            } else if (seg_len == 1 && path[seg_start] == '.') {
            } else if (seg_len == 2 && path[seg_start] == '.' && path[seg_start + 1] == '.') {
                if (ti > 1) {
                    if (tmp[ti - 1] == '/' && ti > 1) ti--;
                    while (ti > 0 && tmp[ti - 1] != '/') ti--;
                }
                if (ti == 0) tmp[ti++] = '/';
            } else {
                if (ti == 0 || tmp[ti - 1] != '/') tmp[ti++] = '/';
                for (size_t k = 0; k < seg_len; k++) {
                    if (ti < sizeof tmp - 1) tmp[ti++] = path[seg_start + k];
                }
            }
            seg_start = i + 1;
        }
    }
    if (ti == 0) tmp[ti++] = '/';
    tmp[ti] = '\0';
    strncpy(path, tmp, MAX_PATH - 1);
    path[MAX_PATH - 1] = '\0';
}

static inline const char *pm_apply_mapping_pairs(const char *in,
                                                const char *pairs[][2],
                                                int pairs_len,
                                                char *out,
                                                size_t out_size)
{
    for (int i = 0; i < pairs_len; i++) {
        const char *from = pairs[i][0];
        const char *to = pairs[i][1];
        size_t from_len = pm_pathlen(from);
        if (pm_path_prefix_matches(from, in)) {
            size_t to_len = pm_pathlen(to);
            size_t tail_len = strlen(in) - from_len;
            if (to_len + tail_len + 1 >= out_size) break;
            memcpy(out, to, to_len);
            memcpy(out + to_len, in + from_len, tail_len + 1);
            return out;
        }
    }
    return in;
}

static inline int pm_parse_path_mapping_env(const char *env,
                                           char ***linear_pairs_out, // array of 2*N char* entries
                                           int *pairs_len_out,
                                           char **buffer_out) // caller frees both
{
    if (!env || !*env) {
        *linear_pairs_out = NULL; *pairs_len_out = 0; *buffer_out = NULL; return 0;
    }
    size_t buffersize = strlen(env) + 1;
    char *buf = (char *)malloc(buffersize);
    if (!buf) return -1;
    memcpy(buf, env, buffersize);

    // Count pairs separated by commas
    int n_pairs = 1;
    for (size_t i = 0; env[i]; i++) if (env[i] == ',') n_pairs++;

    char **linear = (char **)malloc(2 * n_pairs * sizeof(char *));
    if (!linear) { free(buf); return -1; }

    int idx = 0;
    char *pair_start = buf;
    size_t buf_len = strlen(buf);
    for (size_t i = 0; i <= buf_len; i++) {
        if (buf[i] == ',' || buf[i] == '\0') {
            buf[i] = '\0'; // terminate current pair
            char *colon = strchr(pair_start, ':');
            if (!colon) { free(buf); free(linear); return -2; } // missing colon in pair
            *colon = '\0'; // split pair into FROM and TO
            linear[idx++] = pair_start;     // FROM
            linear[idx++] = colon + 1;      // TO
            pair_start = &buf[i + 1];       // start of next pair
        }
    }
    *linear_pairs_out = linear;
    *pairs_len_out = n_pairs;
    *buffer_out = buf;
    return 0;
}

// Common structures for path mapping configuration
struct pm_mapping_config {
    const char *mappings[64][2];
    size_t mapping_count;
    unsigned char mapping_is_malloced[64];
    const char *excludes[64];
    size_t exclude_count;
    unsigned char exclude_is_malloced[64];
};

// Common functions for path mapping management
static inline void pm_cleanup_mappings(struct pm_mapping_config *config)
{
    for (size_t i = 0; i < config->mapping_count; i++) {
        if (config->mapping_is_malloced[i]) {
            free((void*)config->mappings[i][0]);
            free((void*)config->mappings[i][1]);
        }
    }
}

static inline void pm_cleanup_excludes(struct pm_mapping_config *config)
{
    for (size_t i = 0; i < config->exclude_count; i++) {
        if (config->exclude_is_malloced[i]) {
            free((void*)config->excludes[i]);
        }
    }
}

static inline int pm_is_excluded_prefix(const char *abs_path, const struct pm_mapping_config *config)
{
    if (!abs_path || abs_path[0] != '/') return 0;
    for (size_t i = 0; i < config->exclude_count; i++) {
        if (pm_path_prefix_matches(config->excludes[i], abs_path)) return 1;
    }
    return 0;
}

static inline void pm_load_mappings_from_env(const char *env, struct pm_mapping_config *config)
{
    config->mapping_count = 0;
    // Initialize mapping_is_malloced array
    for (size_t i = 0; i < sizeof(config->mapping_is_malloced) / sizeof(config->mapping_is_malloced[0]); i++) {
        config->mapping_is_malloced[i] = 0;
    }

    if (!env || !*env) {
        // Use default mappings
        size_t limit = sizeof config->mappings / sizeof config->mappings[0];
        for (size_t i = 0; i < pm_default_mapping_count && i < limit; i++) {
            config->mappings[config->mapping_count][0] = pm_default_mappings[i][0];
            config->mappings[config->mapping_count][1] = pm_default_mappings[i][1];
            config->mapping_is_malloced[config->mapping_count] = 0;
            config->mapping_count++;
        }
        return;
    }

    char **linear = NULL;
    char *buf = NULL;
    int pairs_len = 0;
    if (pm_parse_path_mapping_env(env, &linear, &pairs_len, &buf) != 0) return;

    size_t limit = sizeof config->mappings / sizeof config->mappings[0];
    for (int i = 0; i < pairs_len && config->mapping_count < limit; i++) {
        config->mappings[config->mapping_count][0] = strdup(linear[i * 2 + 0]);
        config->mappings[config->mapping_count][1] = strdup(linear[i * 2 + 1]);
        config->mapping_is_malloced[config->mapping_count] = 1;
        config->mapping_count++;
    }
    free(linear);
    free(buf);
}

static inline void pm_load_excludes_from_env(const char *env, struct pm_mapping_config *config)
{
    config->exclude_count = 0;
    if (!env || !*env) {
        // Apply defaults
        size_t limit = sizeof config->excludes / sizeof config->excludes[0];
        for (size_t i = 0; i < pm_default_exclude_count && i < limit; i++) {
            config->excludes[i] = pm_default_excludes[i];
            config->exclude_is_malloced[i] = 0;
            config->exclude_count++;
        }
        return;
    }

    const char *p = env;
    while (*p && config->exclude_count < (sizeof config->excludes / sizeof config->excludes[0])) {
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        if (len > 0) {
            char *s = (char *)malloc(MAX_PATH);
            if (!s) break;
            size_t copy = len < (MAX_PATH - 1) ? len : (MAX_PATH - 1);
            memcpy(s, start, copy);
            s[copy] = '\0';
            pm_normalize_path_inplace(s);
            config->excludes[config->exclude_count] = s;
            config->exclude_is_malloced[config->exclude_count] = 1;
            config->exclude_count++;
        }
        if (*p == ',') p++;
    }
}

static inline const char *pm_apply_mapping_with_config(const char *in, char *out, size_t out_size, const struct pm_mapping_config *config)
{
    return pm_apply_mapping_pairs(in, (const char *(*)[2])config->mappings, (int)config->mapping_count, out, out_size);
}


// Implementation of symlink resolution with virtual directory support
static inline const char* pm_resolve_symlink_path_impl(const char *original_path, const char *mapped_path, char *resolved_buffer, size_t buffer_size, const struct pm_mapping_config *config)
{
    if (mapped_path == original_path) {
        // No mapping applied, return original path
        return original_path;
    }

    // Check if the file is a symlink
    struct stat st;
    if (lstat(mapped_path, &st) == 0 && S_ISLNK(st.st_mode)) {
        ssize_t len = readlink(mapped_path, resolved_buffer, buffer_size - 1);
        if (len > 0) {
            resolved_buffer[len] = '\0';

            // If target is relative, resolve it relative to virtual directory
            if (resolved_buffer[0] != '/') {
                // Get virtual directory from original path
                char virtual_dir[MAX_PATH];
                strncpy(virtual_dir, original_path, sizeof(virtual_dir) - 1);
                virtual_dir[sizeof(virtual_dir) - 1] = '\0';
                char *last_slash = strrchr(virtual_dir, '/');
                if (last_slash) {
                    *last_slash = '\0';
                } else {
                    strcpy(virtual_dir, ".");
                }

                // Resolve target relative to virtual directory
                char abs_resolved[MAX_PATH];
                if (snprintf(abs_resolved, sizeof(abs_resolved), "%s/%s", virtual_dir, resolved_buffer) < sizeof(abs_resolved)) {
                    pm_normalize_path_inplace(abs_resolved);

                    // Apply mapping to resolved path directly (avoid recursion)
                    char mapped_resolved[MAX_PATH];
                    const char *final_resolved = pm_apply_mapping_with_config(abs_resolved, mapped_resolved, sizeof mapped_resolved, config);

                    // Copy to output buffer
                    strncpy(resolved_buffer, final_resolved, buffer_size - 1);
                    resolved_buffer[buffer_size - 1] = '\0';
                    return resolved_buffer;
                }
            } else {
                // Target is absolute, apply mapping to it directly (avoid recursion)
                char mapped_resolved[MAX_PATH];
                const char *final_resolved = pm_apply_mapping_with_config(resolved_buffer, mapped_resolved, sizeof mapped_resolved, config);

                // Copy to output buffer
                strncpy(resolved_buffer, final_resolved, buffer_size - 1);
                resolved_buffer[buffer_size - 1] = '\0';
                return resolved_buffer;
            }
        }
    }

    // Not a symlink or resolution failed, return mapped path
    return mapped_path;
}

// Helper function to determine if symlink resolution should be applied
static inline int pm_should_resolve_symlink(const char *function_name, int relsymlink)
{
    int is_readlink_function = (strstr(function_name, "readlink") != NULL);

    if (is_readlink_function) {
        // For readlink functions, never resolve symlinks (return symlink content, not resolved path)
        return 0;
    } else {
        // For all other functions, resolve when PATHMAP_RELSYMLINK=1
        return relsymlink ? 1 : 0;
    }
}

// Universal function for updating argv[0] when redirecting paths
// Returns NULL if no update needed, or a new argv array that must be freed by caller
static inline char** pm_update_argv0(const char *original_path, const char *new_path, char * const* argv)
{
    if (new_path == original_path || argv == NULL || argv[0] == NULL) {
        return NULL; // No need to update
    }

    // Create new argv array with updated argv[0]
    int argc = 0;
    while (argv[argc] != NULL) argc++;

    char **new_argv = malloc((argc + 1) * sizeof(char*));
    if (new_argv != NULL) {
        // For symlinks, keep the original filename in argv[0] for programs like busybox
        // that determine their behavior based on argv[0]
        const char *original_filename = strrchr(original_path, '/');
        if (original_filename != NULL) {
            original_filename++; // Skip the '/'
        } else {
            original_filename = original_path;
        }

        // Get directory from new_path
        char new_dir[MAX_PATH];
        strncpy(new_dir, new_path, sizeof(new_dir) - 1);
        new_dir[sizeof(new_dir) - 1] = '\0';
        char *last_slash = strrchr(new_dir, '/');
        if (last_slash != NULL) {
            *last_slash = '\0';
        } else {
            strcpy(new_dir, ".");
        }

        // Allocate memory for new argv[0]
        char *new_argv0 = malloc(MAX_PATH);
        if (new_argv0 != NULL) {
            // Combine new directory with original filename
            if (snprintf(new_argv0, MAX_PATH, "%s/%s", new_dir, original_filename) < MAX_PATH) {
                // Success - use the combined path
                new_argv[0] = new_argv0;
            } else {
                // Fallback to mapped path
                free(new_argv0);
                new_argv[0] = (char*)new_path;
            }
        } else {
            // Fallback to mapped path if allocation fails
            new_argv[0] = (char*)new_path;
        }

        for (int i = 1; i < argc; i++) {
            new_argv[i] = argv[i];      // Copy remaining arguments
        }
        new_argv[argc] = NULL;
    }
    return new_argv;
}

// Helper function to free argv array created by pm_update_argv0
static inline void pm_free_argv0(char **new_argv, const char *new_path)
{
    if (new_argv != NULL) {
        // Free the allocated argv[0] string if it was allocated
        if (new_argv[0] != (char*)new_path) {
            free(new_argv[0]);
        }
        free(new_argv);
    }
}

// Common debug/logging system
typedef enum {
    PM_LOG_QUIET = 0,
    PM_LOG_INFO = 1,
    PM_LOG_DEBUG = 2
} pm_log_level_t;

static pm_log_level_t g_pm_log_level = PM_LOG_QUIET;

static inline void pm_init_logging(void)
{
    const char *env_debug = getenv("PATHMAP_DEBUG");
    if (!env_debug || !*env_debug) {
        g_pm_log_level = PM_LOG_QUIET;
        return;
    }
    if (strcmp(env_debug, "0") == 0) {
        g_pm_log_level = PM_LOG_QUIET;
        return;
    }
    if (strcmp(env_debug, "1") == 0) {
        g_pm_log_level = PM_LOG_INFO;
        return;
    }
    // Any other non-zero value treated as full debug
    g_pm_log_level = PM_LOG_DEBUG;
}

static inline void pm_set_log_level(pm_log_level_t level)
{
    g_pm_log_level = level;
}

static inline pm_log_level_t pm_get_log_level(void)
{
    return g_pm_log_level;
}

#define pm_info_fprintf(...)  do { if (g_pm_log_level >= PM_LOG_INFO) fprintf(__VA_ARGS__); } while(0)
#define pm_debug_fprintf(...) do { if (g_pm_log_level >= PM_LOG_DEBUG) fprintf(__VA_ARGS__); } while(0)
#define pm_error_fprintf fprintf // always print errors

// Common initialization structure
struct pm_common_config {
    struct pm_mapping_config mapping_config;
    int relsymlink;
    int debug;
    int dry_run;
};

static inline void pm_init_common_config(struct pm_common_config *config)
{
    memset(config, 0, sizeof(*config));
    pm_init_logging();
    config->debug = (g_pm_log_level >= PM_LOG_INFO);

    // Load mappings from environment
    const char *env_string = getenv("PATH_MAPPING");
    pm_load_mappings_from_env(env_string, &config->mapping_config);

    // Load exclusions from environment
    const char *excl = getenv("PATH_MAPPING_EXCLUDE");
    pm_load_excludes_from_env(excl, &config->mapping_config);

    // Check for relative symlink resolution control
    const char *relsymlink_env = getenv("PATHMAP_RELSYMLINK");
    config->relsymlink = (relsymlink_env && strcmp(relsymlink_env, "1") == 0);

    // Print mappings and excludes when debug is enabled
    for (size_t i = 0; i < config->mapping_config.mapping_count; i++) {
        pm_info_fprintf(stderr, "PATH_MAPPING[%zu]: %s => %s\n", i,
                       config->mapping_config.mappings[i][0],
                       config->mapping_config.mappings[i][1]);
    }
    for (size_t i = 0; i < config->mapping_config.exclude_count; i++) {
        pm_info_fprintf(stderr, "PATH_MAPPING_EXCLUDE[%zu]: %s\n", i,
                       config->mapping_config.excludes[i]);
    }
}

static inline void pm_cleanup_common_config(struct pm_common_config *config)
{
    pm_cleanup_mappings(&config->mapping_config);
    pm_cleanup_excludes(&config->mapping_config);
}

// Common path mapping function with full logic
static inline const char *pm_fix_path_common(const char *function_name,
                                            const char *path,
                                            char *new_path,
                                            size_t new_path_size,
                                            const struct pm_common_config *config)
{
    if (path == NULL) return path;

    // If relative, resolve against CWD and normalize .. and . components
    const char *match_path = path;
    char absbuf[MAX_PATH];
    if (path[0] != '/') {
        // Build base using /proc/self/cwd to avoid getcwd syscall (seccomp-friendly)
        char base[MAX_PATH];
        ssize_t n = readlink("/proc/self/cwd", base, sizeof base - 1);
        if (n <= 0) {
            // Fallback: can't resolve, skip mapping
            return path;
        }
        base[n] = '\0';
        // Join base and path into absbuf
        size_t bl = strlen(base);
        absbuf[0] = '\0';
        strncpy(absbuf, base, sizeof absbuf - 1);
        absbuf[sizeof absbuf - 1] = '\0';
        if (bl == 0 || absbuf[bl - 1] != '/') strncat(absbuf, "/", sizeof absbuf - strlen(absbuf) - 1);
        strncat(absbuf, path, sizeof absbuf - strlen(absbuf) - 1);

        // Normalize path
        pm_normalize_path_inplace(absbuf);
        match_path = absbuf;
    } else {
        // Normalize absolute path to collapse sequences like "/.//" so prefix match works
        strncpy(absbuf, path, sizeof absbuf - 1);
        absbuf[sizeof absbuf - 1] = '\0';
        pm_normalize_path_inplace(absbuf);
        match_path = absbuf;
    }

    // Exclusions: if match_path lies under any excluded prefix, skip mapping
    if (pm_is_excluded_prefix(match_path, &config->mapping_config)) {
        return path;
    }

    // Only apply mapping if the normalized path starts with one of the redirected prefixes
    int should_map = 0;
    for (size_t i = 0; i < config->mapping_config.mapping_count; i++) {
        if (pm_path_prefix_matches(config->mapping_config.mappings[i][0], match_path)) {
            should_map = 1;
            break;
        }
    }

    if (!should_map) {
        return path;
    }

    const char *mapped = pm_apply_mapping_with_config(match_path, new_path, new_path_size, &config->mapping_config);
    if (mapped != match_path) {
        pm_info_fprintf(stderr, "Mapped Path: %s('%s') => '%s'\n", function_name, match_path, mapped);

        // Resolve symlinks with virtual directory support (only if mapping applied)
        if (pm_should_resolve_symlink(function_name, config->relsymlink)) {
            char resolved_buffer[MAX_PATH];
            const char *final_path = pm_resolve_symlink_path_impl(match_path, mapped, resolved_buffer, sizeof resolved_buffer, &config->mapping_config);
            if (final_path != mapped) {
                pm_info_fprintf(stderr, "Symlink Resolved: %s('%s') => '%s'\n", function_name, mapped, final_path);
                // Copy resolved path to output buffer
                strncpy(new_path, final_path, new_path_size - 1);
                new_path[new_path_size - 1] = '\0';
                return new_path;
            }
        }

        return mapped;
    }
    return path;
}

// Common argv[0] update function (improved version)
static inline char **pm_update_argv0_common(const char *original_path,
                                           const char *new_path,
                                           char * const* argv,
                                           const struct pm_common_config *config)
{
    if (new_path == original_path || argv == NULL || argv[0] == NULL) {
        return NULL; // No need to update
    }

    // Always set argv[0] to mapped(original_path) without symlink resolve.
    // If mapping doesn't change it, do nothing and print nothing.
    char mapped0[MAX_PATH];
    const char *mapped = pm_apply_mapping_with_config(original_path, mapped0, sizeof mapped0, &config->mapping_config);
    if (mapped == NULL) {
        return NULL;
    }
    if (strcmp(mapped, original_path) == 0) {
        // No change to argv[0]
        return NULL;
    }

    int argc = 0;
    while (argv[argc] != NULL) argc++;
    char **new_argv = (char **)malloc((argc + 1) * sizeof(char*));
    if (!new_argv) {
        return NULL;
    }
    char *dup = strdup(mapped);
    if (!dup) {
        free(new_argv);
        return NULL;
    }
    new_argv[0] = dup;
    for (int i = 1; i < argc; i++) new_argv[i] = argv[i];
    new_argv[argc] = NULL;
    pm_info_fprintf(stderr, "argv0: '%s' => '%s'\n", original_path, new_argv[0]);
    return new_argv;
}

// Common execution with resolved path and updated argv[0]
static inline int pm_execute_with_resolved_path_universal(const char *original_path,
                                                         const char *final_path,
                                                         char * const* argv,
                                                         char * const* env,
                                                         void *exec_func,
                                                         int has_env,
                                                         const struct pm_common_config *config)
{
    // Update argv[0] if path changed
    char **new_argv = pm_update_argv0_common(original_path, final_path, argv, config);

    if (new_argv != NULL) {
        int result;
        if (has_env) {
            // execve signature: (const char *, char * const*, char * const*)
            int (*exec_func_with_env)(const char *, char * const*, char * const*) = exec_func;
            result = exec_func_with_env(final_path, new_argv, env);
        } else {
            // execvp signature: (const char *, char * const*)
            int (*exec_func_without_env)(const char *, char * const*) = exec_func;
            result = exec_func_without_env(final_path, new_argv);
        }
        pm_free_argv0(new_argv, final_path);
        return result;
    }

    // No argv update needed
    if (has_env) {
        int (*exec_func_with_env)(const char *, char * const*, char * const*) = exec_func;
        return exec_func_with_env(final_path, argv, env);
    } else {
        int (*exec_func_without_env)(const char *, char * const*) = exec_func;
        return exec_func_without_env(final_path, argv);
    }
}

#endif

