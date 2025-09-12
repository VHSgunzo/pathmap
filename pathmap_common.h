#ifndef PATHMAP_COMMON_H
#define PATHMAP_COMMON_H

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#include <string.h>
#include <stddef.h>
#include <stdlib.h>

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

#endif

