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
#include <limits.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fnmatch.h>
#include <errno.h>

// Feature defaults (edit here to enable by default)
// #define PM_DEFAULT_DEBUG 1
// #define PM_DEFAULT_RELSYMLINK 1
#define PM_DEFAULT_REVERSE_ENABLED 1

#ifndef PM_DEFAULT_DEBUG
#define PM_DEFAULT_DEBUG 0
#endif
#ifndef PM_DEFAULT_RELSYMLINK
#define PM_DEFAULT_RELSYMLINK 0
#endif
#ifndef PM_DEFAULT_REVERSE_ENABLED
#define PM_DEFAULT_REVERSE_ENABLED 0
#endif

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
// Capture star-only glob segments in pattern against path. Supports only '*' metas and enforces FNM_PATHNAME semantics
// Returns number of captures (>=0) on success, -1 on failure. caps[i] points into 'path'.
static inline int pm_capture_stars(const char *pattern,
                                   const char *path,
                                   const char **caps,
                                   size_t *caplens,
                                   size_t maxcaps)
{
    if (strchr(pattern, '?') || strchr(pattern, '[')) return -1; // only '*'
    size_t cap_index = 0;
    const char *pp = pattern;
    const char *sp = path;
    while (*pp) {
        // copy literal until '*'
        const char *aster = strchr(pp, '*');
        size_t litlen = aster ? (size_t)(aster - pp) : strlen(pp);
        if (litlen) {
            if (strncmp(sp, pp, litlen) != 0) return -1;
            sp += litlen;
            pp += litlen;
        }
        if (*pp == '*') {
            pp++; // skip '*'
            // Find what comes after '*' in pattern
            if (*pp == '\0') {
                // '*' at end: capture everything to end of path
                size_t seglen = strlen(sp);
                if (cap_index < maxcaps) { caps[cap_index] = sp; caplens[cap_index] = seglen; }
                cap_index++;
                sp += seglen;
            } else if (*pp == '/') {
                // '*' before '/': capture up to next '/' (single segment)
                const char *seg_end = strchr(sp, '/');
                if (!seg_end) return -1; // must have '/' in path
                size_t seglen = (size_t)(seg_end - sp);
                if (cap_index < maxcaps) { caps[cap_index] = sp; caplens[cap_index] = seglen; }
                cap_index++;
                sp += seglen;
            } else {
                // '*' before literal: find where literal starts in path
                // Find length of literal (until next '*' or '/')
                const char *literal_start = pp;
                size_t literal_len = 0;
                const char *next_aster = strchr(pp, '*');
                const char *next_slash = strchr(pp, '/');
                // Literal ends at next '*' or '/' or end of pattern
                const char *literal_end = pp;
                if (next_aster && next_slash) {
                    literal_end = (next_aster < next_slash) ? next_aster : next_slash;
                } else if (next_aster) {
                    literal_end = next_aster;
                } else if (next_slash) {
                    literal_end = next_slash;
                } else {
                    literal_end = pp + strlen(pp);
                }
                literal_len = (size_t)(literal_end - pp);
                
                // Search for literal in remaining path (greedy: find last occurrence if multiple)
                const char *found = NULL;
                // Try to find the literal, but respect segment boundaries
                // If literal contains '/', we can search anywhere; otherwise search within current segment
                if (memchr(literal_start, '/', literal_len) != NULL) {
                    // Literal contains '/': search from current position
                    size_t path_remaining = strlen(sp);
                    for (const char *search = sp; search + literal_len <= sp + path_remaining; search++) {
                        if (memcmp(search, literal_start, literal_len) == 0) {
                            found = search;
                        }
                    }
                } else {
                    // Literal doesn't contain '/': search within current segment (until next '/' or end)
                    const char *seg_end = strchr(sp, '/');
                    size_t seg_remaining = seg_end ? (size_t)(seg_end - sp) : strlen(sp);
                    // Find last occurrence of literal within segment
                    for (const char *search = sp; search + literal_len <= sp + seg_remaining; search++) {
                        if (memcmp(search, literal_start, literal_len) == 0) {
                            found = search;
                        }
                    }
                }
                if (!found) return -1; // literal not found
                // Capture everything before the literal
                size_t seglen = (size_t)(found - sp);
                if (cap_index < maxcaps) { caps[cap_index] = sp; caplens[cap_index] = seglen; }
                cap_index++;
                sp = found; // sp points to literal; it will be advanced by literal matching in next iteration
            }
        }
    }
    // After pattern end, path must also end
    if (*sp != '\0') return -1;
    return (int)(cap_index > maxcaps ? maxcaps : cap_index);
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

    // Count pairs separated by commas or newlines
    int n_pairs = 1;
    for (size_t i = 0; env[i]; i++) {
        if (env[i] == ',' || env[i] == '\n' || env[i] == '\r') n_pairs++;
    }

    char **linear = (char **)malloc(2 * n_pairs * sizeof(char *));
    if (!linear) { free(buf); return -1; }

    int idx = 0;
    char *pair_start = buf;
    size_t buf_len = strlen(buf);
    // Helper: trim leading/trailing spaces and tabs in-place
    auto char *pm_trim_ws(char *s) {
        while (*s == ' ' || *s == '\t') s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
        *e = '\0';
        return s;
    }
    for (size_t i = 0; i <= buf_len; i++) {
        if (buf[i] == ',' || buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\0') {
            buf[i] = '\0'; // terminate current pair
            char *segment = pm_trim_ws(pair_start);
            if (*segment == '\0') { pair_start = &buf[i + 1]; continue; } // skip empty entry
            char *colon = strchr(segment, ':');
            if (!colon) { pair_start = &buf[i + 1]; continue; } // skip invalid entry without colon
            *colon = '\0'; // split pair into FROM and TO
            char *from = pm_trim_ws(segment);
            char *to = pm_trim_ws(colon + 1);
            if (*from == '\0' || *to == '\0') { pair_start = &buf[i + 1]; continue; } // require both sides
            linear[idx++] = from;     // FROM
            linear[idx++] = to;       // TO
            pair_start = &buf[i + 1];       // start of next pair
        }
    }
    *linear_pairs_out = linear;
    *pairs_len_out = idx / 2;
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
    unsigned char mapping_is_glob[64];
    unsigned char exclude_is_glob[64];
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
        const char *pat = config->excludes[i];
        if (config->exclude_is_glob[i]) {
            if (fnmatch(pat, abs_path, FNM_PATHNAME) == 0) return 1;
        } else {
            if (pm_path_prefix_matches(pat, abs_path)) return 1;
        }
    }
    return 0;
}

static inline void pm_load_mappings_from_env(const char *env, struct pm_mapping_config *config)
{
    config->mapping_count = 0;
    // Initialize mapping_is_malloced array
    for (size_t i = 0; i < sizeof(config->mapping_is_malloced) / sizeof(config->mapping_is_malloced[0]); i++) {
        config->mapping_is_malloced[i] = 0;
        config->mapping_is_glob[i] = 0;
    }

    if (!env || !*env) {
        // Use default mappings
        size_t limit = sizeof config->mappings / sizeof config->mappings[0];
        for (size_t i = 0; i < pm_default_mapping_count && i < limit; i++) {
            config->mappings[config->mapping_count][0] = pm_default_mappings[i][0];
            config->mappings[config->mapping_count][1] = pm_default_mappings[i][1];
            config->mapping_is_malloced[config->mapping_count] = 0;
            config->mapping_is_glob[config->mapping_count] = 0;
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
        const char *from_in = linear[i * 2 + 0];
        const char *to_in = linear[i * 2 + 1];
        config->mappings[config->mapping_count][0] = strdup(from_in);
        config->mappings[config->mapping_count][1] = strdup(to_in);
        config->mapping_is_malloced[config->mapping_count] = 1;
        // Mark glob if pattern contains wildcard/meta
        config->mapping_is_glob[config->mapping_count] = (strpbrk(from_in, "*?[") != NULL) ? 1 : 0;
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
            config->exclude_is_glob[i] = 0;
            config->exclude_count++;
        }
        return;
    }

    const char *p = env;
    while (*p && config->exclude_count < (sizeof config->excludes / sizeof config->excludes[0])) {
        const char *start = p;
        while (*p && *p != ',' && *p != '\n' && *p != '\r') p++;
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
            config->exclude_is_glob[config->exclude_count] = (strpbrk(s, "*?[") != NULL) ? 1 : 0;
            config->exclude_count++;
        }
        if (*p == ',' || *p == '\n' || *p == '\r') p++;
    }
}

static inline const char *pm_apply_mapping_with_config(const char *in, char *out, size_t out_size, const struct pm_mapping_config *config)
{
    // Guard against recursive mapping: if input path already contains any TO prefix, don't map it
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *to = config->mappings[i][1];
        if (pm_path_prefix_matches(to, in)) {
            return in; // Already mapped, don't map again
        }
    }
    
    // Choose the best match among prefixes and globs. Prefer longer matched portion.
    ssize_t best_index = -1;
    size_t best_match_len = 0;
    size_t best_from_len = 0;
    const char *best_tail = NULL;
    int best_has_captured_tail = 0;
    const char *best_caps[8];
    size_t best_caplens[8];
    int best_capcount = 0;
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *from = config->mappings[i][0];
        if (config->mapping_is_glob[i]) {
            // Support simple trailing '*' capture: prefix before '*' must match as path segment prefix
            const char *aster = strchr(from, '*');
            if (aster && strchr(aster + 1, '*') == NULL && strchr(from, '?') == NULL && strchr(from, '[') == NULL) {
                size_t pref_len = (size_t)(aster - from);
                if (strncmp(from, in, pref_len) == 0) {
                    // Relaxed: accept prefix match even if not ending with '/'
                    const char *captured_start = in + pref_len;
                    size_t captured_len;
                    if (aster[1] == '\0') {
                        // '*' at end: capture everything to end of input path
                        captured_len = strlen(captured_start);
                    } else if (aster[1] == '/') {
                        // '*' before '/': capture only until next '/'
                        const char *next_slash = strchr(captured_start, '/');
                        captured_len = next_slash ? (size_t)(next_slash - captured_start) : strlen(captured_start);
                    } else {
                        // '*' followed by literal: capture within current segment until next '/'
                        const char *next_slash = strchr(captured_start, '/');
                        captured_len = next_slash ? (size_t)(next_slash - captured_start) : strlen(captured_start);
                    }
                    size_t match_len = pref_len;
                    if (match_len >= best_match_len) {
                        best_match_len = match_len;
                        best_index = (ssize_t)i;
                        best_from_len = pref_len;
                        best_tail = captured_start;
                        best_has_captured_tail = 1;
                        // Provide one capture for substitution in TO
                        best_capcount = 1;
                        best_caps[0] = captured_start;
                        best_caplens[0] = captured_len;
                    }
                }
            } else {
                int capcount = 0;
                const char *caps[8];
                size_t caplens[8];
                if (strchr(from, '*') && !strchr(from, '?') && !strchr(from, '[')) {
                    capcount = pm_capture_stars(from, in, caps, caplens, 8);
                }
                if (capcount >= 0 || fnmatch(from, in, FNM_PATHNAME) == 0) {
                    size_t match_len = strlen(in);
                    if (match_len >= best_match_len) {
                        best_match_len = match_len;
                        best_index = (ssize_t)i;
                        best_from_len = strlen(in);
                        best_tail = "";
                        best_has_captured_tail = 0;
                        if (capcount > 0) {
                            best_capcount = capcount;
                            for (int ci = 0; ci < capcount && ci < 8; ci++) { best_caps[ci] = caps[ci]; best_caplens[ci] = caplens[ci]; }
                        } else { best_capcount = 0; }
                    }
                }
            }
        } else {
            if (pm_path_prefix_matches(from, in)) {
                size_t from_len = pm_pathlen(from);
                if (from_len > best_match_len) {
                    best_match_len = from_len;
                    best_index = (ssize_t)i;
                    best_from_len = from_len;
                    best_tail = in + from_len;
                    best_has_captured_tail = 0;
                }
            }
        }
    }
    if (best_index >= 0) {
        const char *to = config->mappings[best_index][1];
        const char *tail = best_tail ? best_tail : "";
        size_t to_len = strlen(to);
        size_t tail_len = strlen(tail);
        const char *star_in_to = strchr(to, '*');
        if (best_capcount > 0) {
            // Replace sequential '*' in TO by captured segments
            size_t pos = 0;
            size_t i_to = 0;
            int capi = 0;
            while (to[i_to] != '\0') {
                if (to[i_to] == '*' && capi < best_capcount) {
                    // Check what comes after '*' in TO pattern
                    int after_star_is_slash = (to[i_to + 1] == '/');
                    int after_star_is_end = (to[i_to + 1] == '\0');
                    
                    // Add separator before capture only if needed (when at segment boundary)
                    if (pos > 0 && out[pos - 1] != '/' && best_caps[capi][0] != '/') {
                        // Only add separator if '*' is at a segment boundary (before '/')
                        if (i_to > 0 && to[i_to - 1] == '/') {
                            if (pos + 1 >= out_size) return in; 
                            out[pos++] = '/';
                        }
                    }
                    
                    // Insert captured content
                    if (pos + best_caplens[capi] >= out_size) return in;
                    memcpy(out + pos, best_caps[capi], best_caplens[capi]); pos += best_caplens[capi];
                    i_to++; // skip '*'
                    
                    // If '*' was followed by '/' in pattern, add separator and skip it in pattern
                    // For literals after '*', just skip '*' and continue normally (no separator)
                    if (after_star_is_slash) {
                        // Add '/' after captured part if needed
                        if (pos > 0 && out[pos - 1] != '/') {
                            if (pos + 1 >= out_size) return in;
                            out[pos++] = '/';
                        }
                        // Skip the '/' in pattern since we already added it
                        i_to++;
                    }
                    capi++;
                    continue;
                }
                if (pos + 1 >= out_size) return in;
                out[pos++] = to[i_to++];
            }
            out[pos] = '\0';
            return out;
        }
        if (best_has_captured_tail && star_in_to) {
            size_t left_len = (size_t)(star_in_to - to);
            const char *right = star_in_to + 1;
            size_t right_len = strlen(right);
            int need_sep_left = (left_len > 0 && to[left_len - 1] != '/' && tail_len > 0 && tail[0] != '/');
            int need_sep_right = (right_len > 0 && tail_len > 0 && tail[tail_len - 1] != '/' && right[0] != '/');
            size_t total = left_len + (size_t)need_sep_left + tail_len + (size_t)need_sep_right + right_len + 1;
            if (total < out_size) {
                size_t pos = 0;
                if (left_len) { memcpy(out + pos, to, left_len); pos += left_len; }
                if (need_sep_left) { out[pos++] = '/'; }
                if (tail_len) { memcpy(out + pos, tail, tail_len); pos += tail_len; }
                if (need_sep_right) { out[pos++] = '/'; }
                if (right_len) { memcpy(out + pos, right, right_len); pos += right_len; }
                out[pos] = '\0';
                return out;
            }
        }
        // Default join: TO + optional '/' + tail
        int need_sep = (to_len > 0 && to[to_len - 1] != '/' && tail_len > 0 && tail[0] != '/');
        if (to_len + (size_t)need_sep + tail_len + 1 < out_size) {
            memcpy(out, to, to_len);
            size_t pos = to_len;
            if (need_sep) { out[pos++] = '/'; }
            memcpy(out + pos, tail, tail_len + 1);
            return out;
        }
    }
    return in;
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
        g_pm_log_level = PM_DEFAULT_DEBUG ? PM_LOG_INFO : PM_LOG_QUIET;
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
    int reverse_enabled;
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

    // Check for relative symlink resolution control (env overrides default)
    const char *relsymlink_env = getenv("PATHMAP_RELSYMLINK");
    config->relsymlink = relsymlink_env ? (strcmp(relsymlink_env, "1") == 0) : PM_DEFAULT_RELSYMLINK;
    // Reverse mapping enable switch (env overrides default)
    const char *reverse_env = getenv("PATHMAP_REVERSE");
    config->reverse_enabled = reverse_env ? (strcmp(reverse_env, "1") == 0) : PM_DEFAULT_REVERSE_ENABLED;

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
// Helper: check if absolute path lies under any FROM (virtual) prefix
static inline int pm_is_under_any_from_prefix(const char *abs_path, const struct pm_mapping_config *config)
{
    if (!abs_path || abs_path[0] != '/') return 0;
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *from = config->mappings[i][0];
        if (pm_path_prefix_matches(from, abs_path)) return 1;
    }
    return 0;
}

// Helper: check if absolute path lies under any TO (real) prefix
static inline int pm_is_under_any_to_prefix(const char *abs_path, const struct pm_mapping_config *config)
{
    if (!abs_path || abs_path[0] != '/') return 0;
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *to = config->mappings[i][1];
        if (config->mapping_is_glob[i]) {
            if (fnmatch(to, abs_path, FNM_PATHNAME) == 0) return 1;
        } else {
            if (pm_path_prefix_matches(to, abs_path)) return 1;
        }
    }
    return 0;
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
    // Never remap the literal current directory
    if (path[0] == '.' && path[1] == '\0') return path;

    // Respect PATH-based resolution semantics for exec* functions that search PATH.
    // For names without '/', do not absolutize against CWD and do not map; let libc PATH search handle it.
    if (function_name && path[0] != '/' && strchr(path, '/') == NULL) {
        if (strcmp(function_name, "execvp") == 0 ||
            strcmp(function_name, "execvpe") == 0 ||
            strcmp(function_name, "execlp") == 0 ||
            strcmp(function_name, "posix_spawnp") == 0) {
            return path;
        }
    }

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

    // Try to apply mapping (supports prefixes and globs). If unchanged, return original path.
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

// Reverse mapping: map a real filesystem path back to its virtual counterpart
static inline const char *pm_apply_reverse_mapping_with_config(const char *in,
                                                             char *out,
                                                             size_t out_size,
                                                             const struct pm_mapping_config *config)
{
    if (!in || !*in) return in;
    if (out_size < 2) return in;
    
    // Prefer the most specific match. Support TO-globs with star captures.
    ssize_t best_index = -1;
    size_t best_score = 0; // longer match wins
    int best_capcount = 0;
    const char *best_caps[8];
    size_t best_caplens[8];
    int best_to_has_star = 0;
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *to = config->mappings[i][1];
        int to_is_glob = (strpbrk(to, "*?[") != NULL) ? 1 : 0;
        if (to_is_glob) {
            // Capture stars on TO against the real path 'in'
            const char *caps[8]; size_t caplens[8];
            int capcount = -1;
            if (strchr(to, '*') && !strchr(to, '?') && !strchr(to, '[')) {
                capcount = pm_capture_stars(to, in, caps, caplens, 8);
            }
            if (capcount >= 0 || fnmatch(to, in, FNM_PATHNAME) == 0) {
                size_t score = strlen(in);
                if (score >= best_score) {
                    best_score = score;
                    best_index = (ssize_t)i;
                    best_capcount = capcount > 0 ? capcount : 0;
                    for (int k = 0; k < best_capcount; k++) { best_caps[k] = caps[k]; best_caplens[k] = caplens[k]; }
                    best_to_has_star = (strchr(to, '*') != NULL);
                }
            }
        } else {
            if (pm_path_prefix_matches(to, in)) {
                size_t score = pm_pathlen(to);
                if (score > best_score) {
                    best_score = score;
                    best_index = (ssize_t)i;
                    best_capcount = 0;
                    best_to_has_star = 0;
                }
            }
        }
    }
    if (best_index >= 0) {
        const char *from = config->mappings[best_index][0];
        const char *to = config->mappings[best_index][1];
        // If we have captures from TO and FROM contains '*', substitute them sequentially
        if (best_capcount > 0 && strchr(from, '*') != NULL) {
            size_t pos = 0; size_t i_from = 0; int capi = 0;
            while (from[i_from] != '\0') {
                if (from[i_from] == '*' && capi < best_capcount) {
                    if (pos > 0 && out[pos - 1] != '/' && best_caps[capi][0] != '/') {
                        if (pos + 1 >= out_size) return in; 
                        out[pos++] = '/';
                    }
                    if (pos + best_caplens[capi] >= out_size) return in;
                    memcpy(out + pos, best_caps[capi], best_caplens[capi]); pos += best_caplens[capi];
                    i_from++;
                    if (from[i_from] != '\0' && from[i_from] != '/' && pos > 0 && out[pos - 1] != '/') {
                        if (pos + 1 >= out_size) return in; 
                        out[pos++] = '/';
                    }
                    capi++;
                    continue;
                }
                if (pos + 1 >= out_size) return in;
                out[pos++] = from[i_from++];
            }
            out[pos] = '\0';
            return out;
        }
        // Fallback: plain prefix reverse mapping
        size_t to_len = pm_pathlen(to);
        size_t from_len = pm_pathlen(from);
        size_t tail_len = strlen(in) - to_len;
        if (from_len + tail_len + 1 < out_size) {
            memcpy(out, from, from_len);
            memcpy(out + from_len, in + to_len, tail_len + 1);
            return out;
        }
    }
    return in;
}

// Compute preferred virtual CWD string from a real CWD.
// Returns pointer to either 'out' (when changed) or 'real' (unchanged).
static inline const char *pm_virtualize_cwd_string(const char *real,
                                                  char *out,
                                                  size_t out_size,
                                                  const struct pm_mapping_config *config)
{
    if (!real || !*real) return real;
    // Only virtualize CWD when it lies under some TO (real) prefix
    if (!pm_is_under_any_to_prefix(real, config)) return real;
    char vbuf[MAX_PATH];
    const char *virt = pm_apply_reverse_mapping_with_config(real, vbuf, sizeof vbuf, config);
    if (virt != real) {
        size_t need = strlen(virt) + 1;
        if (need <= out_size) {
            memcpy(out, virt, need);
            return out;
        }
    }
    return real;
}

// Return 1 if path refers to /proc/*/cwd
static inline int pm_is_proc_cwd_path(const char *path)
{
    if (!path) return 0;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    return strstr(path, "/cwd") != NULL;
}

// For readlink results: if path is /proc/*/cwd, always return virtualized CWD in buf
static inline ssize_t pm_virtualize_proc_cwd_readlink_result(const char *path,
                                                            char *buf,
                                                            ssize_t n,
                                                            size_t bufsiz,
                                                            const struct pm_mapping_config *config)
{
    if (!pm_is_proc_cwd_path(path)) return n;
    if (n <= 0) return n;
    char tmp[MAX_PATH];
    size_t copy_in = (size_t)n < (sizeof tmp - 1) ? (size_t)n : (sizeof tmp - 1);
    memcpy(tmp, buf, copy_in);
    tmp[copy_in] = '\0';
    char out[MAX_PATH];
    const char *virt = pm_apply_reverse_mapping_with_config(tmp, out, sizeof out, config);
    if (virt == tmp) return n;
    size_t vlen = strlen(virt);
    size_t tocopy = vlen < bufsiz ? vlen : bufsiz;
    memcpy(buf, virt, tocopy);
    return (ssize_t)tocopy;
}

// Call the real readlink from libc (bypass our interposer)
static inline ssize_t pm_readlink_real(const char *pathname, char *buf, size_t bufsiz)
{
    // In preload builds we prefer calling the real symbol via dlsym(RTLD_NEXT).
    // In tracer builds, there is no interposer; call readlink directly.
#ifdef RTLD_NEXT
    typedef ssize_t (*orig_readlink_func_type_local)(const char *, char *, size_t);
    static orig_readlink_func_type_local orig_readlink_local = NULL;
    if (orig_readlink_local == NULL) {
        orig_readlink_local = (orig_readlink_func_type_local)dlsym(RTLD_NEXT, "readlink");
    }
    if (orig_readlink_local) return orig_readlink_local(pathname, buf, bufsiz);
#endif
    return readlink(pathname, buf, bufsiz);
}

// Plan startup CWD mapping using virtual-first strategy
struct pm_cwd_plan {
    int have_target;
    char chdir_target[MAX_PATH];
    char pwd_value[MAX_PATH];
};

// Real stat that bypasses our interposers where relevant (for directory validation)
static inline int pm_real_stat_is_dir(const char *path)
{
    if (!path || !*path) return 0;
    // Use real libc stat when available via RTLD_NEXT; otherwise plain stat
#ifdef RTLD_NEXT
    typedef int (*orig_stat_func_type_local)(const char *, struct stat *);
    static orig_stat_func_type_local orig_stat_local = NULL;
    if (orig_stat_local == NULL) {
        orig_stat_local = (orig_stat_func_type_local)dlsym(RTLD_NEXT, "stat");
    }
    if (orig_stat_local) {
        struct stat st2;
        if (orig_stat_local(path, &st2) != 0) return 0;
        return S_ISDIR(st2.st_mode) ? 1 : 0;
    }
#endif
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

// Decide if startup cwd needs fixing: forward-mapped real CWD is not a directory or missing
static inline int pm_startup_cwd_needs_fix(const char *real_cwd, const struct pm_mapping_config *config)
{
    if (!real_cwd || !*real_cwd) return 0;
    // Respect excludes: never attempt to remap startup CWD if it lies under an excluded prefix
    if (pm_is_excluded_prefix(real_cwd, config)) return 0;
    char mapped[MAX_PATH];
    const char *fwd = pm_apply_mapping_with_config(real_cwd, mapped, sizeof mapped, config);
    if (fwd == real_cwd) return 0; // no mapping -> leave as is
    return pm_real_stat_is_dir(fwd) ? 0 : 1;
}

// Helper function to set fallback to root directory
static inline void pm_set_root_fallback(struct pm_cwd_plan *out_plan)
{
    strncpy(out_plan->chdir_target, "/", sizeof(out_plan->chdir_target) - 1);
    strncpy(out_plan->pwd_value, "/", sizeof(out_plan->pwd_value) - 1);
    out_plan->have_target = 1;
}

// Build a validated startup plan and ensure chdir_target is a real directory; fallback to "/"
static inline void pm_build_validated_startup_cwd_plan(const char *real_cwd,
                                                       struct pm_cwd_plan *out_plan,
                                                       const struct pm_mapping_config *config)
{
    memset(out_plan, 0, sizeof(*out_plan));
    
    // Respect excludes: keep current CWD and PWD as-is
    if (real_cwd && pm_is_excluded_prefix(real_cwd, config)) {
        return;
    }
    
    if (!real_cwd || !*real_cwd) return;
    
    // Prefer virtual path first: chdir to its real counterpart, PWD to virtual
    char virt_buf[MAX_PATH];
    const char *virt = pm_virtualize_cwd_string(real_cwd, virt_buf, sizeof virt_buf, config);
    if (virt != real_cwd) {
        // Compute real dir to chdir: forward-map the virtual
        char virt_real_buf[MAX_PATH];
        const char *virt_real = pm_apply_mapping_with_config(virt, virt_real_buf, sizeof virt_real_buf, config);
        if (virt_real == virt) {
            // No forward mapping for the virtual path; stay in current real cwd
            strncpy(out_plan->chdir_target, real_cwd, sizeof(out_plan->chdir_target) - 1);
        } else {
            strncpy(out_plan->chdir_target, virt_real, sizeof(out_plan->chdir_target) - 1);
        }
        strncpy(out_plan->pwd_value, virt, sizeof(out_plan->pwd_value) - 1);
        out_plan->have_target = 1;
    } else {
        // Then try forward mapping
        char fwd_buf[MAX_PATH];
        const char *tgt = pm_apply_mapping_with_config(real_cwd, fwd_buf, sizeof fwd_buf, config);
        if (tgt != real_cwd) {
            // chdir to the real target
            strncpy(out_plan->chdir_target, tgt, sizeof(out_plan->chdir_target) - 1);
            // PWD prefers a virtual representation of the target if available
            const char *pv = pm_virtualize_cwd_string(tgt, out_plan->pwd_value, sizeof(out_plan->pwd_value), config);
            if (pv == tgt) {
                strncpy(out_plan->pwd_value, tgt, sizeof(out_plan->pwd_value) - 1);
            }
            out_plan->have_target = 1;
        } else {
            // Fallback to root
            pm_set_root_fallback(out_plan);
        }
    }
    
    // Validate that the target directory exists
    if (out_plan->have_target && !pm_real_stat_is_dir(out_plan->chdir_target)) {
        // Try user's home directory before final fallback to '/'
        const char *home_env = getenv("HOME");
        char home_buf[MAX_PATH];
        const char *home = NULL;
        if (home_env && *home_env) {
            strncpy(home_buf, home_env, sizeof(home_buf) - 1);
            home_buf[sizeof(home_buf) - 1] = '\0';
            pm_normalize_path_inplace(home_buf);
            home = home_buf;
        } else {
            struct passwd *pw = getpwuid(getuid());
            if (pw && pw->pw_dir && *pw->pw_dir) {
                strncpy(home_buf, pw->pw_dir, sizeof(home_buf) - 1);
                home_buf[sizeof(home_buf) - 1] = '\0';
                pm_normalize_path_inplace(home_buf);
                home = home_buf;
            }
        }
        if (home) {
            // Apply mapping to home directory and check if mapped version exists
            char mapped_home[MAX_PATH];
            const char *mapped_home_path = pm_apply_mapping_with_config(home, mapped_home, sizeof mapped_home, config);
            if (pm_real_stat_is_dir(mapped_home_path)) {
                // chdir target is mapped home; PWD prefers virtualized view if available
                strncpy(out_plan->chdir_target, mapped_home_path, sizeof(out_plan->chdir_target) - 1);
                const char *pv = pm_virtualize_cwd_string(mapped_home_path, out_plan->pwd_value, sizeof(out_plan->pwd_value), config);
                if (pv == mapped_home_path) {
                    strncpy(out_plan->pwd_value, mapped_home_path, sizeof(out_plan->pwd_value) - 1);
                }
                out_plan->have_target = 1;
            } else {
                // Final fallback to root
                pm_set_root_fallback(out_plan);
            }
        } else {
            // Final fallback to root
            pm_set_root_fallback(out_plan);
        }
    }
}

// Reverse-map a readlink result in-place safely. Returns new length (or original n on no change)
static inline ssize_t pm_reverse_readlink_inplace(char *buf,
                                                 ssize_t n,
                                                 size_t bufsiz,
                                                 const struct pm_mapping_config *config)
{
    if (n <= 0) return n;
    char tmp[MAX_PATH];
    size_t copy_in = (size_t)n < (sizeof tmp - 1) ? (size_t)n : (sizeof tmp - 1);
    memcpy(tmp, buf, copy_in);
    tmp[copy_in] = '\0';
    char out[MAX_PATH];
    const char *virt = pm_apply_reverse_mapping_with_config(tmp, out, sizeof out, config);
    if (virt == tmp) return n;
    if (pm_is_excluded_prefix(virt, config)) return n;
    size_t vlen = strlen(virt);
    size_t tocopy = vlen < bufsiz ? vlen : bufsiz;
    memcpy(buf, virt, tocopy);
    return (ssize_t)tocopy;
}

// Universal reverse mapping function that can handle both in-place and allocated string cases
static inline char *pm_reverse_string_result(char *result,
                                            const struct pm_mapping_config *config,
                                            int should_free_original)
{
    if (result == NULL) return NULL;
    char out[MAX_PATH];
    const char *virt = pm_apply_reverse_mapping_with_config(result, out, sizeof out, config);
    if (virt == result) return result; // No change needed
    if (pm_is_excluded_prefix(virt, config)) return result; // Excluded, keep original
    
    // Need to create new string
    size_t len = strlen(virt) + 1;
    char *new_result = malloc(len);
    if (new_result == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(new_result, virt, len);
    if (should_free_original) {
        free(result); // Free original
    }
    return new_result;
}

// Reverse-map a realpath result. Returns new string (allocated) or original if no change needed
static inline char *pm_reverse_realpath_result(char *result,
                                              const struct pm_mapping_config *config)
{
    return pm_reverse_string_result(result, config, 1); // should_free_original = 1
}

// Build full path dirpath + d_name, reverse-map, and return basename into out buffer
// Returns length of new basename (>=0) when changed, or -1 when no change should be applied
static inline int pm_reverse_basename_from_dir(const char *dirpath,
                                              const char *entry_name,
                                              char *out_name,
                                              size_t out_name_size,
                                              const struct pm_mapping_config *config)
{
    // Never rename special entries
    if (entry_name && (strcmp(entry_name, ".") == 0 || strcmp(entry_name, "..") == 0)) {
        return -1;
    }

    // Only apply reverse renames when the directory lies under some mapped TO-prefix
    // This prevents accidental renames in system directories (e.g., /proc, /sys, /dev) or
    // any unrelated paths when PATH_MAPPING does not cover them.
    int dir_under_to_prefix = 0;
    for (size_t i = 0; i < config->mapping_count; i++) {
        const char *to = config->mappings[i][1];
        if (pm_path_prefix_matches(to, dirpath)) { dir_under_to_prefix = 1; break; }
    }
    if (!dir_under_to_prefix) {
        return -1;
    }
    size_t dl = strlen(dirpath);
    size_t nl = strlen(entry_name);
    if (dl + 1 + nl + 1 >= MAX_PATH) return -1;
    char full[MAX_PATH];
    memcpy(full, dirpath, dl);
    full[dl] = '/';
    memcpy(full + dl + 1, entry_name, nl + 1);
    pm_normalize_path_inplace(full);
    char mapped[MAX_PATH];
    const char *virt = pm_apply_reverse_mapping_with_config(full, mapped, sizeof mapped, config);
    if (virt == full) {
        // Fallback heuristic (Case 2): if listing a real directory that is exactly
        // the parent of some mapping TO, and the entry name equals basename(TO),
        // then rename it to basename(FROM). This covers AppDir-like layouts
        // where children have "dirty" real names (e.g., usr-123) but should
        // appear as clean virtual names (e.g., usr) at the virtual root.
        char dir_norm[MAX_PATH];
        strncpy(dir_norm, dirpath, sizeof dir_norm - 1);
        dir_norm[sizeof dir_norm - 1] = '\0';
        pm_normalize_path_inplace(dir_norm);
        for (size_t i = 0; i < config->mapping_count; i++) {
            const char *from = config->mappings[i][0];
            const char *to   = config->mappings[i][1];
            // Split TO into directory and basename
            char to_copy[MAX_PATH];
            strncpy(to_copy, to, sizeof to_copy - 1);
            to_copy[sizeof to_copy - 1] = '\0';
            char *slash2 = strrchr(to_copy, '/');
            if (!slash2 || slash2 == to_copy) continue;
            *slash2 = '\0';
            const char *to_dir = to_copy;
            const char *to_base = slash2 + 1;
            char to_dir_norm[MAX_PATH];
            strncpy(to_dir_norm, to_dir, sizeof to_dir_norm - 1);
            to_dir_norm[sizeof to_dir_norm - 1] = '\0';
            pm_normalize_path_inplace(to_dir_norm);
            if (strcmp(dir_norm, to_dir_norm) != 0) continue;
            if (strcmp(entry_name, to_base) != 0) continue;
            // New displayed name = basename(FROM)
            const char *fslash = strrchr(from, '/');
            const char *from_base = fslash ? fslash + 1 : from;
            size_t newlen2 = strlen(from_base);
            if (newlen2 == 0) continue;
            if (newlen2 + 1 > out_name_size) continue;
            if (pm_is_excluded_prefix(from, config)) continue;
            memcpy(out_name, from_base, newlen2 + 1);
            return (int)newlen2;
        }
        // Additional virtual-root heuristic: if viewing virtual parent dirname(FROM)
        // and entry matches basename(TO), rename to basename(FROM).
        for (size_t i = 0; i < config->mapping_count; i++) {
            const char *from = config->mappings[i][0];
            const char *to   = config->mappings[i][1];
            // Compute from_dir and from_base
            char from_copy[MAX_PATH];
            strncpy(from_copy, from, sizeof from_copy - 1);
            from_copy[sizeof from_copy - 1] = '\0';
            char *fs = strrchr(from_copy, '/');
            if (!fs || fs == from_copy) continue;
            *fs = '\0';
            const char *from_dir = from_copy;
            const char *from_base = fs + 1;
            char from_dir_norm[MAX_PATH];
            strncpy(from_dir_norm, from_dir, sizeof from_dir_norm - 1);
            from_dir_norm[sizeof from_dir_norm - 1] = '\0';
            pm_normalize_path_inplace(from_dir_norm);
            // Compute to_base
            const char *tb = strrchr(to, '/');
            const char *to_base = tb ? tb + 1 : to;
            if (strcmp(dir_norm, from_dir_norm) != 0) continue;
            if (strcmp(entry_name, to_base) != 0) continue;
            size_t newlen2 = strlen(from_base);
            if (newlen2 == 0) continue;
            if (newlen2 + 1 > out_name_size) continue;
            if (pm_is_excluded_prefix(from, config)) continue;
            memcpy(out_name, from_base, newlen2 + 1);
            return (int)newlen2;
        }
        return -1;
    }
    if (pm_is_excluded_prefix(virt, config)) return -1;
    const char *slash = strrchr(virt, '/');
    const char *newname = slash ? slash + 1 : virt;
    size_t newlen = strlen(newname);
    if (newlen == 0) return -1;
    if (newlen + 1 > out_name_size) return -1;
    memcpy(out_name, newname, newlen + 1);
    return (int)newlen;
}

// Apply reverse basename rename in-place to a directory entry name.
// - dirpath: absolute directory path being listed
// - name: pointer to entry name buffer to modify
// - name_buf_capacity: maximum writable bytes in 'name' (including NUL)
// Returns 1 if changed, 0 if unchanged.
static inline int pm_reverse_basename_apply_inplace(const char *dirpath,
                                                   char *name,
                                                   size_t name_buf_capacity,
                                                   const struct pm_mapping_config *config)
{
    if (!dirpath || !name || name_buf_capacity == 0) return 0;
    // Compute current length within provided capacity
    size_t oldlen = strnlen(name, name_buf_capacity - 1);
    if (oldlen == 0) return 0;
    char tmp_newname[NAME_MAX > 0 ? NAME_MAX + 1 : 256];
    int newlen_int = pm_reverse_basename_from_dir(dirpath, name, tmp_newname, sizeof tmp_newname, config);
    if (newlen_int < 0) return 0;
    size_t newlen = (size_t)newlen_int;
    if (newlen > oldlen) return 0; // avoid overflow within original record
    // Ensure capacity is enough to write new name + NUL
    if (newlen + 1 > name_buf_capacity) return 0;
    memcpy(name, tmp_newname, newlen);
    name[newlen] = '\0';
    return 1;
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

