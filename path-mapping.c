/*
MIT License

Copyright (c) 2022 Fritz Webering

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h> // exit
#include <dlfcn.h> // dlsym
#include <fcntl.h> // stat
#include <dirent.h> // DIR*
#include <stdarg.h> // va_start, va_arg
#include <sys/vfs.h> // statfs
#include <sys/statvfs.h> // statvfs
#include <sys/stat.h> // statx, chmod, chown, stat
#include <unistd.h> // uid_t, gid_t
#include <malloc.h> // for execl
#include <utime.h> // utimebuf
#include <sys/time.h> // struct timeval
#include <sys/types.h> // dev_t
#include <ftw.h> // ftw
#ifdef __GLIBC__
#include <fts.h> // fts (glibc-only)
#endif
#include <assert.h>
#include "pathmap_common.h"
#include <sys/xattr.h> // xattr APIs
#include <glob.h> // glob
#include <spawn.h> // posix_spawn
#include <stddef.h> // offsetof for dirent name sizing
#include <sys/mount.h> // mount, umount
// Forward declaration to avoid depending on linux/openat2.h availability at build time
struct open_how;
struct mount_attr;
#include <mntent.h> // setmntent
#include <errno.h> // errno, ERANGE
#include <sys/inotify.h> // inotify_add_watch
#include <sys/fanotify.h> // fanotify_mark


// Runtime logging control via PATHMAP_DEBUG (0=off, 1=info, 2=debug)
static int g_log_level = 0; // 0: quiet, 1: info, 2: debug

__attribute__((constructor))
static void debug_init()
{
    const char *env_debug = getenv("PATHMAP_DEBUG");
    if (!env_debug || !*env_debug) { g_log_level = 0; return; }
    if (strcmp(env_debug, "0") == 0) { g_log_level = 0; return; }
    if (strcmp(env_debug, "1") == 0) { g_log_level = 1; return; }
    // Any other non-zero value treated as full debug
    g_log_level = 2;
}

// Runtime logging control
#define info_fprintf(...)  do { if (g_log_level >= 1) fprintf(__VA_ARGS__); } while(0)
#define debug_fprintf(...) do { if (g_log_level >= 2) fprintf(__VA_ARGS__); } while(0)

#define error_fprintf fprintf // always print errors

// Enable or disable specific overrides (always includes different variants and the 64 version if applicable)
// #define DISABLE_OPEN
// #define DISABLE_OPENAT
// #define DISABLE_FOPEN
// #define DISABLE_CHDIR
// #define DISABLE_STAT
// #define DISABLE_FSTATAT
// #define DISABLE_STATFS
// #define DISABLE_XSTAT
// #define DISABLE_ACCESS
// #define DISABLE_XATTR
// #define DISABLE_OPENDIR
// #define DISABLE_MKDIR
// #define DISABLE_FTW
// #define DISABLE_FTS
// #define DISABLE_PATHCONF
// #define DISABLE_REALPATH
// #define DISABLE_READLINK
// #define DISABLE_SYMLINK
// #define DISABLE_MKFIFO
// #define DISABLE_MKNOD
// #define DISABLE_TRUNCATE
// #define DISABLE_UTIME
// #define DISABLE_CHMOD
// #define DISABLE_CHOWN
// #define DISABLE_UNLINK
// #define DISABLE_EXEC
// #define DISABLE_RENAME
// #define DISABLE_LINK
// #define DISABLE_SCANDIR
// #define DISABLE_CREAT
// #define DISABLE_STATX
// #define DISABLE_MOUNT
// #define DISABLE_GLOB
// #define DISABLE_SPAWN
// #define DISABLE_DLOPEN
// #define DISABLE_HANDLE
// #define DISABLE_OPENAT2
// #define DISABLE_OPEN_TREE
// #define DISABLE_MOVE_MOUNT
// #define DISABLE_MOUNT_SETATTR
// #define DISABLE_STATMOUNT
// #define DISABLE_INOTIFY
// #define DISABLE_FANOTIFY
// #define DISABLE_PIVOT_ROOT

// List of path pairs. Paths beginning with the first item will be
// translated by replacing the matching part with the second item.
static const char *default_path_map[][2] = {
    { "/tmp/path-mapping/tests/virtual", "/tmp/path-mapping/tests/real" },
};

static const char *(*path_map)[2] = default_path_map;
static int path_map_length = (sizeof default_path_map) / (sizeof default_path_map[0]);
static char *path_map_buffer = NULL;
static char **path_map_linear = NULL; // 2*N entries if env specified
static const char *exclude_list[64];
static int exclude_count = 0;
static int exclude_is_malloced[64];

// Default exclusions when PATH_MAPPING_EXCLUDE is not provided
static const char *default_exclude_list[] = {
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
};
static const int default_exclude_count = (sizeof default_exclude_list) / (sizeof default_exclude_list[0]);


//////////////////////////////////////////////////////////
// Constructor to inspect the PATH_MAPPING env variable //
//////////////////////////////////////////////////////////


__attribute__((constructor))
static void path_mapping_init()
{
    if (path_map != default_path_map) return;

    // If environment variable is set and non-empty, override the default
    const char *env_string = getenv("PATH_MAPPING");
    if (env_string != NULL && strlen(env_string) > 0) {
        int pairs_len = 0;
        char **linear = NULL;
        char *buf = NULL;
        int rc = pm_parse_path_mapping_env(env_string, &linear, &pairs_len, &buf);
        if (rc == -2) {
            error_fprintf(stderr, "PATH_MAPPING must have an even number of parts\n");
            exit(255);
        } else if (rc != 0) {
            error_fprintf(stderr, "PATH_MAPPING out of memory\n");
            exit(255);
        }
        if (pairs_len > 0) {
            path_map_length = pairs_len;
            path_map_linear = linear;
            path_map_buffer = buf;
            path_map = (const char *(*)[2])linear;
        }
    }

    for (int i = 0; i < path_map_length; i++) {
        info_fprintf(stderr, "PATH_MAPPING[%d]: %s => %s\n", i, path_map[i][0], path_map[i][1]);
    }

    // Load exclusions from PATH_MAPPING_EXCLUDE (colon-separated absolute prefixes)
    const char *excl = getenv("PATH_MAPPING_EXCLUDE");
    exclude_count = 0;
    if (excl && *excl) {
        const char *p = excl;
        while (*p && exclude_count < (int)(sizeof exclude_list / sizeof exclude_list[0])) {
            const char *start = p;
            while (*p && *p != ',') p++;
            size_t len = (size_t)(p - start);
            if (len > 0) {
                char *s = (char *)malloc(MAX_PATH);
                if (!s) break;
                size_t copy = len < (MAX_PATH - 1) ? len : (MAX_PATH - 1);
                memcpy(s, start, copy); s[copy] = '\0';
                pm_normalize_path_inplace(s);
                exclude_list[exclude_count] = s;
                exclude_is_malloced[exclude_count] = 1;
                exclude_count++;
            }
            if (*p == ',') p++;
        }
    } else {
        for (int i = 0; i < default_exclude_count && i < (int)(sizeof exclude_list / sizeof exclude_list[0]); i++) {
            exclude_list[i] = default_exclude_list[i];
            exclude_is_malloced[i] = 0;
            exclude_count++;
        }
    }
}

__attribute__((destructor))
static void path_mapping_deinit()
{
    if (path_map != default_path_map) {
        free(path_map_linear);
    }
    free(path_map_buffer);
    for (int i = 0; i < exclude_count; i++) if (exclude_is_malloced[i]) free((void*)exclude_list[i]);
}


/////////////////////////////////////////////////////////
//   Helper functions to do the actual path mapping    //
/////////////////////////////////////////////////////////


// pathlen/path_prefix_matches now provided by pathmap_common.h as pm_pathlen/pm_path_prefix_matches

// Forward decl is now in pathmap_common.h (pm_normalize_path_inplace)

// Check if path matches any defined prefix, and if so, replace it with its substitution
static const char *fix_path(const char *function_name, const char *path, char *new_path, size_t new_path_size)
{
    if (path == NULL) return path;

    // If relative, resolve against CWD and normalize .. and . components (without touching FS)
    const char *match_path = path;
    char absbuf[MAX_PATH];
    if (path[0] != '/') {
        // Build base
        char base[MAX_PATH];
        if (getcwd(base, sizeof base) == NULL) {
            // Fallback: can't resolve, skip mapping
            return path;
        }
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
    for (int i = 0; i < exclude_count; i++) {
        if (pm_path_prefix_matches(exclude_list[i], match_path)) {
            debug_fprintf(stderr, "Excluded Path: %s('%s') under '%s'\n", function_name, match_path, exclude_list[i]);
            return path;
        }
    }
    const char *mapped = pm_apply_mapping_pairs(match_path, path_map, path_map_length, new_path, new_path_size);
    if (mapped != match_path) {
        info_fprintf(stderr, "Mapped Path: %s('%s') => '%s'\n", function_name, path, mapped);
        return mapped;
    }
    return path;
}


// Map a real filesystem path back to its virtual counterpart, if it lies under a mapped target
static const char *reverse_fix_path(const char *function_name, const char *path, char *new_path, size_t new_path_size)
{
    if (path == NULL) return path;

    // For reverse mapping, reuse pm_apply_mapping_pairs by swapping map order logically
    for (int i = 0; i < path_map_length; i++) {
        const char *tmp_pair[1][2] = { { path_map[i][1], path_map[i][0] } };
        const char *mapped = pm_apply_mapping_pairs(path, (const char * (*)[2])tmp_pair, 1, new_path, new_path_size);
        // If reverse-mapped path would fall into an excluded prefix, skip applying it
        if (mapped != path) {
            int excluded = 0;
            for (int j = 0; j < exclude_count; j++) {
                if (pm_path_prefix_matches(exclude_list[j], mapped)) { excluded = 1; break; }
            }
            if (excluded) return path;
        }
        if (mapped != path) {
            info_fprintf(stderr, "Reverse-Mapped Path: %s('%s') => '%s'\n", function_name, path, mapped);
            return mapped;
        }
    }
    return path;
}

// Normalize absolute-like path string by collapsing //, /./, and /../ segments into buffer
// normalize helper now provided by pathmap_common.h as pm_normalize_path_inplace


// Join base directory (from dirfd or getcwd) with a possibly relative path
static const char *absolute_from_dirfd(int dirfd, const char *path, char *buffer, size_t buffer_size)
{
    if (path == NULL) return path;
    if (path[0] == '/') return path; // already absolute

    char base[MAX_PATH];
    ssize_t n = 0;
    if (dirfd == AT_FDCWD) {
        if (getcwd(base, sizeof base) == NULL) return path; // fallback
    } else {
        char linkpath[64];
        snprintf(linkpath, sizeof linkpath, "/proc/self/fd/%d", dirfd);
        n = readlink(linkpath, base, sizeof base - 1);
        if (n <= 0) return path; // fallback
        base[n] = '\0';
    }

    size_t need = strlen(base) + 1 /*slash*/ + strlen(path) + 1;
    if (need > buffer_size) return path; // fallback
    strcpy(buffer, base);
    size_t bl = strlen(buffer);
    if (bl == 0 || buffer[bl - 1] != '/') strcat(buffer, "/");
    strcat(buffer, path);
    return buffer;
}


/////////////////////////////////////////////////////////
// Macro definitions for generating function overrides //
/////////////////////////////////////////////////////////


// Hint for debugging these macros:
// Remove the #define __NL__, then compile with gcc -save-temps.
// Then open path-mapping.i with a text editor and replace __NL__ with newlines.
#define __NL__

// Select argument name i from the variable argument list (ignoring types)
#define OVERRIDE_ARG(i, ...)  OVERRIDE_ARG_##i(__VA_ARGS__)
#define OVERRIDE_ARG_1(type1, arg1, ...)  arg1
#define OVERRIDE_ARG_2(type1, arg1, type2, arg2, ...)  arg2
#define OVERRIDE_ARG_3(type1, arg1, type2, arg2, type3, arg3, ...)  arg3
#define OVERRIDE_ARG_4(type1, arg1, type2, arg2, type3, arg3, type4, arg4, ...)  arg4
#define OVERRIDE_ARG_5(type1, arg1, type2, arg2, type3, arg3, type4, arg4, arg5, ...)  arg5

// Create the function pointer typedef for the function
#define OVERRIDE_TYPEDEF_NAME(funcname) orig_##funcname##_func_type
#define OVERRIDE_TYPEDEF(has_varargs, nargs, returntype, funcname, ...)  typedef returntype (*OVERRIDE_TYPEDEF_NAME(funcname))(OVERRIDE_ARGS(has_varargs, nargs, __VA_ARGS__));

// Create a valid C argument list including types
#define OVERRIDE_ARGS(has_varargs, nargs, ...)  OVERRIDE_ARGS_##nargs(has_varargs, __VA_ARGS__)
#define OVERRIDE_ARGS_1(has_varargs, type1, arg1)  type1 arg1 OVERRIDE_VARARGS(has_varargs)
#define OVERRIDE_ARGS_2(has_varargs, type1, arg1, type2, arg2)  type1 arg1, type2 arg2 OVERRIDE_VARARGS(has_varargs)
#define OVERRIDE_ARGS_3(has_varargs, type1, arg1, type2, arg2, type3, arg3)  type1 arg1, type2 arg2, type3 arg3 OVERRIDE_VARARGS(has_varargs)
#define OVERRIDE_ARGS_4(has_varargs, type1, arg1, type2, arg2, type3, arg3, type4, arg4)  type1 arg1, type2 arg2, type3 arg3, type4 arg4 OVERRIDE_VARARGS(has_varargs)
#define OVERRIDE_ARGS_5(has_varargs, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5 OVERRIDE_VARARGS(has_varargs)
// Print ", ..." in the argument list if has_varargs is 1
#define OVERRIDE_VARARGS(has_varargs) OVERRIDE_VARARGS_##has_varargs
#define OVERRIDE_VARARGS_0
#define OVERRIDE_VARARGS_1 , ...

// Create an argument list without types where one argument is replaced with new_path
#define OVERRIDE_RETURN_ARGS(nargs, path_arg_pos, ...)  OVERRIDE_RETURN_ARGS_##nargs##_##path_arg_pos(__VA_ARGS__)
#define OVERRIDE_RETURN_ARGS_1_1(type1, arg1)  new_path
#define OVERRIDE_RETURN_ARGS_2_1(type1, arg1, type2, arg2)  new_path, arg2
#define OVERRIDE_RETURN_ARGS_2_2(type1, arg1, type2, arg2)  arg1, new_path
#define OVERRIDE_RETURN_ARGS_3_1(type1, arg1, type2, arg2, type3, arg3)  new_path, arg2, arg3
#define OVERRIDE_RETURN_ARGS_3_2(type1, arg1, type2, arg2, type3, arg3)  arg1, new_path, arg3
#define OVERRIDE_RETURN_ARGS_3_3(type1, arg1, type2, arg2, type3, arg3)  arg1, arg2, new_path
#define OVERRIDE_RETURN_ARGS_4_1(type1, arg1, type2, arg2, type3, arg3, type4, arg4)  new_path, arg2, arg3, arg4
#define OVERRIDE_RETURN_ARGS_4_2(type1, arg1, type2, arg2, type3, arg3, type4, arg4)  arg1, new_path, arg3, arg4
#define OVERRIDE_RETURN_ARGS_4_3(type1, arg1, type2, arg2, type3, arg3, type4, arg4)  arg1, arg2, new_path, arg4
#define OVERRIDE_RETURN_ARGS_4_4(type1, arg1, type2, arg2, type3, arg3, type4, arg4)  arg1, arg2, arg3, new_path
#define OVERRIDE_RETURN_ARGS_5_1(type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  new_path, arg2, arg3, arg4, arg5
#define OVERRIDE_RETURN_ARGS_5_2(type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  arg1, new_path, arg3, arg4, arg5
#define OVERRIDE_RETURN_ARGS_5_3(type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  arg1, arg2, new_path, arg4, arg5
#define OVERRIDE_RETURN_ARGS_5_4(type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  arg1, arg2, arg3, new_path, arg5
#define OVERRIDE_RETURN_ARGS_5_5(type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5)  arg1, arg2, arg3, arg4, new_path

// Use this to override a function without varargs
#define OVERRIDE_FUNCTION(nargs, path_arg_pos, returntype, funcname, ...) \
    OVERRIDE_FUNCTION_MODE_GENERIC(0, nargs, path_arg_pos, returntype, funcname, __VA_ARGS__)

// Use this to override a function with a vararg mode that works like open() or openat()
#define OVERRIDE_FUNCTION_VARARGS(nargs, path_arg_pos, returntype, funcname, ...) \
    OVERRIDE_FUNCTION_MODE_GENERIC(1, nargs, path_arg_pos, returntype, funcname, __VA_ARGS__)

#define OVERRIDE_FUNCTION_MODE_GENERIC(has_varargs, nargs, path_arg_pos, returntype, funcname, ...) \
OVERRIDE_TYPEDEF(has_varargs, nargs, returntype, funcname, __VA_ARGS__) \
__NL__ returntype funcname (OVERRIDE_ARGS(has_varargs, nargs, __VA_ARGS__))\
__NL__{\
__NL__    debug_fprintf(stderr, #funcname "(%s) called\n", OVERRIDE_ARG(path_arg_pos, __VA_ARGS__));\
__NL__    char buffer[MAX_PATH];\
__NL__    const char *new_path = fix_path(#funcname, OVERRIDE_ARG(path_arg_pos, __VA_ARGS__), buffer, sizeof buffer);\
__NL__ \
__NL__    static OVERRIDE_TYPEDEF_NAME(funcname) orig_func = NULL;\
__NL__    if (orig_func == NULL) {\
__NL__        orig_func = (OVERRIDE_TYPEDEF_NAME(funcname))dlsym(RTLD_NEXT, #funcname);\
__NL__    }\
__NL__    OVERRIDE_DO_MODE_VARARG(has_varargs, nargs, path_arg_pos, __VA_ARGS__) \
__NL__    return orig_func(OVERRIDE_RETURN_ARGS(nargs, path_arg_pos, __VA_ARGS__));\
__NL__}

// Conditionally expands to the code used to handle the mode argument of open() and openat()
#define OVERRIDE_DO_MODE_VARARG(has_mode_vararg, nargs, path_arg_pos, ...) \
    OVERRIDE_DO_MODE_VARARG_##has_mode_vararg(nargs, path_arg_pos, __VA_ARGS__)
#define OVERRIDE_DO_MODE_VARARG_0(nargs, path_arg_pos, ...) // Do nothing
#define OVERRIDE_DO_MODE_VARARG_1(nargs, path_arg_pos, ...) \
__NL__    if ((flags & O_CREAT) != 0) {\
__NL__        va_list args;\
__NL__        va_start(args, flags);\
__NL__        int mode = va_arg(args, int);\
__NL__        va_end(args);\
__NL__        return orig_func(OVERRIDE_RETURN_ARGS(nargs, path_arg_pos, __VA_ARGS__), mode);\
__NL__    }


/////////////////////////////////////////////////////////
//     Definition of all function overrides below      //
/////////////////////////////////////////////////////////


#ifndef DISABLE_OPEN
OVERRIDE_FUNCTION_VARARGS(2, 1, int, open, const char *, pathname, int, flags)
#ifdef __GLIBC__
OVERRIDE_FUNCTION_VARARGS(2, 1, int, open64, const char *, pathname, int, flags)
#endif
#endif // DISABLE_OPEN


#ifndef DISABLE_OPENAT
typedef int (*orig_openat_func_type)(int dirfd, const char *pathname, int flags, ...);
int openat(int dirfd, const char *pathname, int flags, ...)
{
    debug_fprintf(stderr, "openat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("openat", abs, buffer, sizeof buffer);

    static orig_openat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_openat_func_type)dlsym(RTLD_NEXT, "openat");
    }

    if ((flags & O_CREAT) != 0) {
        va_list args; va_start(args, flags); int mode = va_arg(args, int); va_end(args);
        return orig_func(dirfd, new_path, flags, mode);
    }
    return orig_func(dirfd, new_path, flags);
}
#ifdef __GLIBC__
OVERRIDE_FUNCTION_VARARGS(3, 2, int, openat64, int, dirfd, const char *, pathname, int, flags)
#endif
#endif // DISABLE_OPENAT


#ifndef DISABLE_OPENAT2
typedef int (*orig_openat2_func_type)(int dirfd, const char *pathname, struct open_how *how, size_t size);
int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
    debug_fprintf(stderr, "openat2(%s) called\n", pathname);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("openat2", pathname, buffer, sizeof buffer);
    static orig_openat2_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_openat2_func_type)dlsym(RTLD_NEXT, "openat2");
    }
    return orig_func(dirfd, new_path, how, size);
}
#endif // DISABLE_OPENAT2


#ifndef DISABLE_FOPEN
OVERRIDE_FUNCTION(2, 1, FILE*, fopen, const char *, filename, const char *, mode)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(2, 1, FILE*, fopen64, const char *, filename, const char *, mode)
#endif
OVERRIDE_FUNCTION(3, 1, FILE*, freopen, const char *, filename, const char *, mode, FILE *, stream)
#endif // DISABLE_FOPEN


#ifndef DISABLE_CREAT
#ifdef __GLIBC__
OVERRIDE_FUNCTION(2, 1, int, creat64, const char *, pathname, mode_t, mode)
#endif
#endif // DISABLE_CREAT


#ifndef DISABLE_CHDIR
OVERRIDE_FUNCTION(1, 1, int, chdir, const char *, path)
#endif // DISABLE_CHDIR


#ifndef DISABLE_CHDIR
OVERRIDE_FUNCTION(1, 1, int, chroot, const char *, path)
#endif // DISABLE_CHDIR


#ifndef DISABLE_STAT
OVERRIDE_FUNCTION(2, 1, int, stat, const char *, path, struct stat *, buf)
OVERRIDE_FUNCTION(2, 1, int, lstat, const char *, path, struct stat *, buf)
#endif // DISABLE_STAT


#ifdef __GLIBC__
#ifndef DISABLE_XSTAT
OVERRIDE_FUNCTION(3, 2, int, __xstat, int, ver, const char *, path, struct stat *, stat_buf)
OVERRIDE_FUNCTION(3, 2, int, __lxstat, int, ver, const char *, path, struct stat *, stat_buf)
OVERRIDE_FUNCTION(3, 2, int, __xstat64, int, ver, const char *, path, struct stat64 *, stat_buf)
OVERRIDE_FUNCTION(3, 2, int, __lxstat64, int, ver, const char *, path, struct stat64 *, stat_buf)
#endif // DISABLE_XSTAT
#endif // __GLIBC__


#ifndef DISABLE_FSTATAT
typedef int (*orig_fstatat_func_type)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    debug_fprintf(stderr, "fstatat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("fstatat", abs, buffer, sizeof buffer);
    static orig_fstatat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_fstatat_func_type)dlsym(RTLD_NEXT, "fstatat");
    }
    return orig_func(dirfd, new_path, statbuf, flags);
}
#ifdef __GLIBC__
OVERRIDE_FUNCTION(4, 2, int, fstatat64, int, dirfd, const char *, pathname, struct stat64 *, statbuf, int, flags)
OVERRIDE_FUNCTION(5, 3, int, __fxstatat, int, ver, int, dirfd, const char *, pathname, struct stat *, statbuf, int, flags)
OVERRIDE_FUNCTION(5, 3, int, __fxstatat64, int, ver, int, dirfd, const char *, pathname, struct stat64 *, statbuf, int, flags)
#endif
#endif // DISABLE_FSTATAT


#ifndef DISABLE_STATFS
OVERRIDE_FUNCTION(2, 1, int, statfs, const char *, path, struct statfs *, buf)
OVERRIDE_FUNCTION(2, 1, int, statvfs, const char *, path, struct statvfs *, buf)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(2, 1, int, statfs64, const char *, path, struct statfs64 *, buf)
OVERRIDE_FUNCTION(2, 1, int, statvfs64, const char *, path, struct statvfs64 *, buf)
#endif
#endif // DISABLE_STATFS


#ifndef DISABLE_ACCESS
OVERRIDE_FUNCTION(2, 1, int, access, const char *, pathname, int, mode)
typedef int (*orig_faccessat_func_type)(int dirfd, const char *pathname, int mode, int flags);
int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    debug_fprintf(stderr, "faccessat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("faccessat", abs, buffer, sizeof buffer);
    static orig_faccessat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_faccessat_func_type)dlsym(RTLD_NEXT, "faccessat");
    }
    return orig_func(dirfd, new_path, mode, flags);
}
#endif // DISABLE_ACCESS


#ifndef DISABLE_XATTR
OVERRIDE_FUNCTION(4, 1, ssize_t, getxattr, const char *, path, const char *, name, void *, value, size_t, size)
OVERRIDE_FUNCTION(4, 1, ssize_t, lgetxattr, const char *, path, const char *, name, void *, value, size_t, size)
#endif // DISABLE_XATTR


#ifndef DISABLE_XATTR
OVERRIDE_FUNCTION(5, 1, int, setxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
OVERRIDE_FUNCTION(5, 1, int, lsetxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
OVERRIDE_FUNCTION(2, 1, int, removexattr, const char *, path, const char *, name)
OVERRIDE_FUNCTION(2, 1, int, lremovexattr, const char *, path, const char *, name)
OVERRIDE_FUNCTION(3, 1, ssize_t, listxattr, const char *, path, char *, list, size_t, size)
OVERRIDE_FUNCTION(3, 1, ssize_t, llistxattr, const char *, path, char *, list, size_t, size)
#endif // DISABLE_XATTR


#ifndef DISABLE_OPENDIR
OVERRIDE_FUNCTION(1, 1, DIR *, opendir, const char *, name)
#endif // DISABLE_OPENDIR


#ifndef DISABLE_MKDIR
OVERRIDE_FUNCTION(2, 1, int, mkdir, const char *, pathname, mode_t, mode)
#endif // DISABLE_MKDIR


#ifndef DISABLE_MKDIR
OVERRIDE_FUNCTION(3, 2, int, mkdirat, int, dirfd, const char *, pathname, mode_t, mode)
#endif // DISABLE_MKDIR


#ifndef DISABLE_FTW
#ifdef __GLIBC__
OVERRIDE_FUNCTION(3, 1, int, ftw, const char *, filename, __ftw_func_t, func, int, descriptors)
OVERRIDE_FUNCTION(4, 1, int, nftw, const char *, filename, __nftw_func_t, func, int, descriptors, int, flags)
OVERRIDE_FUNCTION(3, 1, int, ftw64, const char *, filename, __ftw64_func_t, func, int, descriptors)
OVERRIDE_FUNCTION(4, 1, int, nftw64, const char *, filename, __nftw64_func_t, func, int, descriptors, int, flags)
#else
/* musl does not expose GNU __ftw_* typedefs; skip FTW wrappers */
#endif
#endif // DISABLE_FTW


#ifdef __GLIBC__
#ifndef DISABLE_FTS
typedef int (*fts_compare_func_t)(const FTSENT **, const FTSENT **);
typedef FTS* (*orig_fts_open_func_type)(char * const *path_argv, int options, fts_compare_func_t compare);
FTS *fts_open(char * const *path_argv, int options, fts_compare_func_t compare)
{
    if (path_argv[0] == NULL) return NULL;
    debug_fprintf(stderr, "fts_open(%s) called\n", path_argv[0]);

    FTS *result = NULL;
    int argc = 0;
    const char **new_paths;
    char **buffers;

    for (argc = 0; path_argv[argc] != NULL; argc++) {} // count number of paths in argument array

    buffers = malloc((argc + 1) * sizeof(char *));
    if (buffers == NULL) {
        goto _fts_open_return;
    }
    for (int i = 0; i < argc; i++) { buffers[i] = NULL; } // Initialize for free() in case of failure

    new_paths = malloc((argc + 1) * sizeof(char *));
    if (new_paths == NULL) {
        goto _fts_open_cleanup_buffers;
    }
    for (int i = 0; i < argc; i++) {
        buffers[i] = malloc(MAX_PATH + 1);
        if (buffers[i] == NULL) {
            goto _fts_open_cleanup;
        }
        new_paths[i] = fix_path("fts_open", path_argv[i], buffers[i], MAX_PATH);
    }
    new_paths[argc] = NULL; // terminating null pointer

    static orig_fts_open_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_fts_open_func_type)dlsym(RTLD_NEXT, "fts_open");
    }

    result = orig_func((char * const *)new_paths, options, compare);

_fts_open_cleanup:
    for (int i = 0; i < argc; i++) {
        free(buffers[i]);
    }
    free(new_paths);
_fts_open_cleanup_buffers:
    free(buffers);
_fts_open_return:
    return result;
}
#endif // DISABLE_FTS
#endif // __GLIBC__


#ifndef DISABLE_PATHCONF
OVERRIDE_FUNCTION(2, 1, long, pathconf, const char *, path, int, name)
#endif // DISABLE_PATHCONF


#ifndef DISABLE_REALPATH
OVERRIDE_FUNCTION(2, 1, char *, realpath, const char *, path, char *, resolved_path)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(1, 1, char *, canonicalize_file_name, const char *, path)
#endif
#endif // DISABLE_REALPATH


#ifndef DISABLE_CHDIR
typedef char *(*orig_getcwd_func_type)(char *buf, size_t size);
char *getcwd(char *buf, size_t size)
{
    debug_fprintf(stderr, "getcwd() called\n");
    static orig_getcwd_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_getcwd_func_type)dlsym(RTLD_NEXT, "getcwd");
    }
    char *result = orig_func(buf, size);
    if (result == NULL) return result;
    char buffer[MAX_PATH];
    const char *mapped = reverse_fix_path("getcwd", result, buffer, sizeof buffer);
    if (mapped == result) return result;
    // Copy back into caller's buffer or allocate if buf == NULL per POSIX
    if (buf != NULL) {
        size_t len = strlen(mapped) + 1;
        if (len > size) {
            errno = ERANGE;
            return NULL;
        }
        strcpy(buf, mapped);
        return buf;
    } else {
        return strdup(mapped);
    }
}

#ifdef __GLIBC__
typedef char *(*orig_get_current_dir_name_func_type)(void);
char *get_current_dir_name(void)
{
    debug_fprintf(stderr, "get_current_dir_name() called\n");
    static orig_get_current_dir_name_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_get_current_dir_name_func_type)dlsym(RTLD_NEXT, "get_current_dir_name");
    }
    char *result = orig_func();
    if (result == NULL) return result;
    char buffer[MAX_PATH];
    const char *mapped = reverse_fix_path("get_current_dir_name", result, buffer, sizeof buffer);
    if (mapped == result) return result;
    free(result);
    return strdup(mapped);
}

typedef char *(*orig_getwd_func_type)(char *buf);
char *getwd(char *buf)
{
    debug_fprintf(stderr, "getwd() called\n");
    static orig_getwd_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_getwd_func_type)dlsym(RTLD_NEXT, "getwd");
    }
    char *result = orig_func(buf);
    if (result == NULL) return result;
    char buffer[MAX_PATH];
    const char *mapped = reverse_fix_path("getwd", result, buffer, sizeof buffer);
    if (mapped == result) return result;
    if (buf != NULL) {
        strcpy(buf, mapped);
        return buf;
    }
    return strdup(mapped);
}
#endif // __GLIBC__
#endif // DISABLE_CHDIR

#ifndef DISABLE_READLINK
typedef ssize_t (*orig_readlink_func_type)(const char *pathname, char *buf, size_t bufsiz);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    debug_fprintf(stderr, "readlink(%s) called\n", pathname);
    char inbuf[MAX_PATH];
    const char *in = fix_path("readlink", pathname, inbuf, sizeof inbuf);
    static orig_readlink_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_readlink_func_type)dlsym(RTLD_NEXT, "readlink");
    }
    ssize_t n = orig_func(in, buf, bufsiz);
    if (n > 0 && buf != NULL && bufsiz > 0) {
        // NUL-terminate into a temp buffer to apply reverse mapping
        char tmp[MAX_PATH];
        size_t copy = (size_t)n < sizeof tmp - 1 ? (size_t)n : sizeof tmp - 1;
        memcpy(tmp, buf, copy); tmp[copy] = '\0';
        pm_normalize_path_inplace(tmp);
        char out[MAX_PATH];
        const char *virt = reverse_fix_path("readlink", tmp, out, sizeof out);
        if (virt != tmp) {
            size_t vlen = strlen(virt);
            size_t writelen = vlen < bufsiz ? vlen : bufsiz;
            memcpy(buf, virt, writelen);
            return (ssize_t)writelen;
        }
    }
    return n;
}

typedef ssize_t (*orig_readlinkat_func_type)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    debug_fprintf(stderr, "readlinkat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char inbuf[MAX_PATH];
    const char *in = fix_path("readlinkat", abs, inbuf, sizeof inbuf);
    static orig_readlinkat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_readlinkat_func_type)dlsym(RTLD_NEXT, "readlinkat");
    }
    ssize_t n = orig_func(dirfd, in, buf, bufsiz);
    if (n > 0 && buf != NULL && bufsiz > 0) {
        char tmp[MAX_PATH];
        size_t copy = (size_t)n < sizeof tmp - 1 ? (size_t)n : sizeof tmp - 1;
        memcpy(tmp, buf, copy); tmp[copy] = '\0';
        pm_normalize_path_inplace(tmp);
        char out[MAX_PATH];
        const char *virt = reverse_fix_path("readlinkat", tmp, out, sizeof out);
        if (virt != tmp) {
            size_t vlen = strlen(virt);
            size_t writelen = vlen < bufsiz ? vlen : bufsiz;
            memcpy(buf, virt, writelen);
            return (ssize_t)writelen;
        }
    }
    return n;
}
#endif // DISABLE_READLINK


#ifndef DISABLE_SYMLINK
typedef int (*orig_symlink_func_type)(const char *target, const char *linkpath);
int symlink(const char *target, const char *linkpath)
{
    debug_fprintf(stderr, "symlink(target=%s, linkpath=%s) called\n", target, linkpath);
    // Map linkpath fully via fix_path
    char lbuf[MAX_PATH];
    const char *new_link = fix_path("symlink-link", linkpath, lbuf, sizeof lbuf);
    // Map target forward without forcing absolute: use apply_mapping directly
    char tout[MAX_PATH];
    const char *new_target = pm_apply_mapping_pairs(target, (const char *(*)[2])path_map, path_map_length, tout, sizeof tout);
    static orig_symlink_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_symlink_func_type)dlsym(RTLD_NEXT, "symlink");
    }
    return orig_func(new_target, new_link);
}

typedef int (*orig_symlinkat_func_type)(const char *target, int newdirfd, const char *linkpath);
int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    debug_fprintf(stderr, "symlinkat(target=%s, linkpath=%s) called\n", target, linkpath);
    // Resolve linkpath relative to dirfd then map via fix_path
    char absbuf[MAX_PATH];
    const char *abs_link = absolute_from_dirfd(newdirfd, linkpath, absbuf, sizeof absbuf);
    char lbuf[MAX_PATH];
    const char *new_link = fix_path("symlinkat-link", abs_link, lbuf, sizeof lbuf);
    // Map target forward directly
    char tout[MAX_PATH];
    const char *new_target = pm_apply_mapping_pairs(target, (const char *(*)[2])path_map, path_map_length, tout, sizeof tout);
    static orig_symlinkat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_symlinkat_func_type)dlsym(RTLD_NEXT, "symlinkat");
    }
    return orig_func(new_target, newdirfd, new_link);
}
#endif // DISABLE_SYMLINK

// Readdir family: reverse-map entry names if their full paths are under a mapped target
static int resolve_fd_path_self(int fd, char *out, size_t out_size)
{
    char linkp[64];
    snprintf(linkp, sizeof linkp, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(linkp, out, out_size - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    return 0;
}

#ifndef DISABLE_OPENDIR
typedef struct dirent *(*orig_readdir_func_type)(DIR *dirp);
struct dirent *readdir(DIR *dirp)
{
    static orig_readdir_func_type orig_func = NULL;
    if (orig_func == NULL) orig_func = (orig_readdir_func_type)dlsym(RTLD_NEXT, "readdir");
    struct dirent *ent = orig_func(dirp);
    if (!ent) return ent;
    int fd = dirfd(dirp);
    if (fd < 0) return ent;
    char dirpath[MAX_PATH];
    if (resolve_fd_path_self(fd, dirpath, sizeof dirpath) != 0) return ent;
    size_t dl = strlen(dirpath);
    size_t nl = strlen(ent->d_name);
    if (dl + 1 + nl + 1 >= MAX_PATH) return ent;
    char full[MAX_PATH];
    memcpy(full, dirpath, dl); full[dl] = '/'; memcpy(full + dl + 1, ent->d_name, nl + 1);
    pm_normalize_path_inplace(full);
    char out[MAX_PATH];
    const char *virt = reverse_fix_path("readdir", full, out, sizeof out);
    if (virt == full) return ent;
    const char *slash = strrchr(virt, '/');
    const char *newname = slash ? slash + 1 : virt;
    size_t newlen = strlen(newname);
    if (newlen <= nl) {
        memcpy(ent->d_name, newname, newlen + 1);
        return ent;
    }
    static __thread struct dirent *tls_ent = NULL;
    static __thread size_t tls_cap = 0;
    size_t need = offsetof(struct dirent, d_name) + newlen + 1;
    if (need > tls_cap) {
        size_t newcap = need;
        struct dirent *nb = (struct dirent *)realloc(tls_ent, newcap);
        if (!nb) return ent; // fallback
        tls_ent = nb; tls_cap = newcap;
    }
    // Copy header fields, then write new name
    *tls_ent = *ent;
    memcpy(tls_ent->d_name, newname, newlen + 1);
#ifdef _DIRENT_HAVE_D_RECLEN
    tls_ent->d_reclen = (unsigned short)need;
#endif
    return tls_ent;
}
#ifdef __GLIBC__
typedef struct dirent64 *(*orig_readdir64_func_type)(DIR *dirp);
struct dirent64 *readdir64(DIR *dirp)
{
    static orig_readdir64_func_type orig_func = NULL;
    if (orig_func == NULL) orig_func = (orig_readdir64_func_type)dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *ent = orig_func(dirp);
    if (!ent) return ent;
    int fd = dirfd(dirp);
    if (fd < 0) return ent;
    char dirpath[MAX_PATH];
    if (resolve_fd_path_self(fd, dirpath, sizeof dirpath) != 0) return ent;
    size_t dl = strlen(dirpath);
    size_t nl = strlen(ent->d_name);
    if (dl + 1 + nl + 1 >= MAX_PATH) return ent;
    char full[MAX_PATH];
    memcpy(full, dirpath, dl); full[dl] = '/'; memcpy(full + dl + 1, ent->d_name, nl + 1);
    pm_normalize_path_inplace(full);
    char out[MAX_PATH];
    const char *virt = reverse_fix_path("readdir64", full, out, sizeof out);
    if (virt == full) return ent;
    const char *slash = strrchr(virt, '/');
    const char *newname = slash ? slash + 1 : virt;
    size_t newlen = strlen(newname);
    if (newlen <= nl) {
        memcpy(ent->d_name, newname, newlen + 1);
        return ent;
    }
    static __thread struct dirent64 *tls_ent64 = NULL;
    static __thread size_t tls_cap64 = 0;
    size_t need = offsetof(struct dirent64, d_name) + newlen + 1;
    if (need > tls_cap64) {
        size_t newcap = need;
        struct dirent64 *nb = (struct dirent64 *)realloc(tls_ent64, newcap);
        if (!nb) return ent; // fallback
        tls_ent64 = nb; tls_cap64 = newcap;
    }
    *tls_ent64 = *ent;
    memcpy(tls_ent64->d_name, newname, newlen + 1);
#ifdef _DIRENT_HAVE_D_RECLEN
    tls_ent64->d_reclen = (unsigned short)need;
#endif
    return tls_ent64;
}
#endif
#endif // DISABLE_OPENDIR


#ifndef DISABLE_MKFIFO
OVERRIDE_FUNCTION(2, 1, int, mkfifo, const char *, filename, mode_t, mode)
#endif // DISABLE_MKFIFO


#ifndef DISABLE_CREAT
// mk*temp family (template is a path-like string)
OVERRIDE_FUNCTION(1, 1, int, mkstemp, char *, template)
OVERRIDE_FUNCTION(2, 1, int, mkostemp, char *, template, int, flags)
OVERRIDE_FUNCTION(2, 1, int, mkstemps, char *, template, int, suffixlen)
OVERRIDE_FUNCTION(3, 1, int, mkostemps, char *, template, int, suffixlen, int, flags)
OVERRIDE_FUNCTION(1, 1, char *, mkdtemp, char *, template)
#endif // DISABLE_CREAT


#ifndef DISABLE_MKNOD
OVERRIDE_FUNCTION(3, 1, int, mknod, const char *, filename, mode_t, mode, dev_t, dev)
#endif // DISABLE_MKNOD


#ifndef DISABLE_MKFIFO
OVERRIDE_FUNCTION(3, 2, int, mkfifoat, int, dirfd, const char *, pathname, mode_t, mode)
#endif // DISABLE_MKFIFO


#ifndef DISABLE_MKNOD
OVERRIDE_FUNCTION(4, 2, int, mknodat, int, dirfd, const char *, pathname, mode_t, mode, dev_t, dev)
#endif // DISABLE_MKNOD


#ifndef DISABLE_TRUNCATE
OVERRIDE_FUNCTION(2, 1, int, truncate, const char *, path, off_t, length)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(2, 1, int, truncate64, const char *, path, off64_t, length)
#endif
#endif // DISABLE_TRUNCATE


#ifndef DISABLE_UTIME
OVERRIDE_FUNCTION(2, 1, int, utime, const char *, filename, const struct utimbuf *, times)
OVERRIDE_FUNCTION(2, 1, int, utimes, const char *, filename, const struct timeval *, tvp)
OVERRIDE_FUNCTION(2, 1, int, lutime, const char *, filename, const struct utimbuf *, tvp)
OVERRIDE_FUNCTION(4, 2, int, utimensat, int, dirfd, const char *, pathname, const struct timespec *, times, int, flags)
typedef int (*orig_futimesat_func_type)(int dirfd, const char *pathname, const struct timeval times[2]);
int futimesat(int dirfd, const char *pathname, const struct timeval times[2])
{
    debug_fprintf(stderr, "futimesat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("futimesat", abs, buffer, sizeof buffer);
    static orig_futimesat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_futimesat_func_type)dlsym(RTLD_NEXT, "futimesat");
    }
    return orig_func(dirfd, new_path, times);
}
#endif // DISABLE_UTIME


#ifndef DISABLE_CHMOD
OVERRIDE_FUNCTION(2, 1, int, chmod, const char *, pathname, mode_t, mode)
OVERRIDE_FUNCTION(4, 2, int, fchmodat, int, dirfd, const char *, pathname, mode_t, mode, int, flags)
#endif // DISABLE_CHMOD


#ifndef DISABLE_CHOWN
OVERRIDE_FUNCTION(3, 1, int, chown, const char *, pathname, uid_t, owner, gid_t, group)
OVERRIDE_FUNCTION(3, 1, int, lchown, const char *, pathname, uid_t, owner, gid_t, group)
OVERRIDE_FUNCTION(5, 2, int, fchownat, int, dirfd, const char *, pathname, uid_t, owner, gid_t, group, int, flags)
#endif // DISABLE_CHOWN


#ifndef DISABLE_UNLINK
OVERRIDE_FUNCTION(1, 1, int, unlink, const char *, pathname)
typedef int (*orig_unlinkat_func_type)(int dirfd, const char *pathname, int flags);
int unlinkat(int dirfd, const char *pathname, int flags)
{
    debug_fprintf(stderr, "unlinkat(%s) called\n", pathname);
    char absbuf[MAX_PATH];
    const char *abs = absolute_from_dirfd(dirfd, pathname, absbuf, sizeof absbuf);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("unlinkat", abs, buffer, sizeof buffer);
    static orig_unlinkat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_unlinkat_func_type)dlsym(RTLD_NEXT, "unlinkat");
    }
    return orig_func(dirfd, new_path, flags);
}
OVERRIDE_FUNCTION(1, 1, int, rmdir, const char *, pathname)
OVERRIDE_FUNCTION(1, 1, int, remove, const char *, pathname)
#endif // DISABLE_UNLINK


#ifndef DISABLE_EXEC
OVERRIDE_FUNCTION(2, 1, int, execv, const char *, filename, char * const*, argv)
OVERRIDE_FUNCTION(3, 1, int, execve, const char *, filename, char * const*, argv, char * const*, env)
OVERRIDE_FUNCTION(2, 1, int, execvp, const char *, filename, char * const*, argv)
OVERRIDE_FUNCTION(3, 1, int, execvpe, const char *, filename, char * const*, argv, char * const*, env)
OVERRIDE_FUNCTION(5, 2, int, execveat, int, dirfd, const char *, pathname, char * const*, argv, char * const*, env, int, flags)

int execl(const char *filename, const char *arg0, ...)
{
    debug_fprintf(stderr, "execl(%s) called\n", filename);

    char buffer[MAX_PATH];
    const char *new_path = fix_path("execl", filename, buffer, sizeof buffer);

    // Note: call execv, not execl, because we can't call varargs functions with an unknown number of args
    static orig_execv_func_type execv_func = NULL;
    if (execv_func == NULL) {
        execv_func = (orig_execv_func_type)dlsym(RTLD_NEXT, "execv");
    }

    // count args
    int argc = 1;
    va_list args_list;
    va_start(args_list, arg0);
    while (va_arg(args_list, char *) != NULL) argc += 1;
    va_end(args_list);

    // extract args
    const char **argv_buffer = malloc(sizeof(char *) * (argc + 1));
    va_start(args_list, arg0);
    argv_buffer[0] = arg0;
    argc = 1;
    char *arg = NULL;
    while ((arg = va_arg(args_list, char *)) != NULL) {
        argv_buffer[argc++] = arg;
    }
    va_end(args_list);
    argv_buffer[argc] = NULL;

    int result = execv_func(new_path, (char * const*)argv_buffer);
    free(argv_buffer); // We ONLY reach this if exec fails, so we need to clean up
    return result;
}

int execlp(const char *filename, const char *arg0, ...)
{
    debug_fprintf(stderr, "execlp(%s) called\n", filename);

    char buffer[MAX_PATH];
    const char *new_path = fix_path("execlp", filename, buffer, sizeof buffer);

    // Note: call execvp, not execlp, because we can't call varargs functions with an unknown number of args
    static orig_execvp_func_type execvp_func = NULL;
    if (execvp_func == NULL) {
        execvp_func = (orig_execvp_func_type)dlsym(RTLD_NEXT, "execvp");
    }

    // count args
    int argc = 1;
    va_list args_list;
    va_start(args_list, arg0);
    while (va_arg(args_list, char *) != NULL) argc += 1;
    va_end(args_list);

    // extract args
    const char **argv_buffer = malloc(sizeof(char *) * (argc + 1));
    va_start(args_list, arg0);
    argv_buffer[0] = arg0;
    argc = 1;
    char *arg = NULL;
    while ((arg = va_arg(args_list, char *)) != NULL) {
        argv_buffer[argc++] = arg;
    }
    va_end(args_list);
    argv_buffer[argc] = NULL;

    int result = execvp_func(new_path, (char * const*)argv_buffer);
    free(argv_buffer); // We ONLY reach this if exec fails, so we need to clean up
    return result;
}

int execle(const char *filename, const char *arg0, ... /* , char *const env[] */)
{
    debug_fprintf(stderr, "execl(%s) called\n", filename);

    char buffer[MAX_PATH];
    const char *new_path = fix_path("execle", filename, buffer, sizeof buffer);

    // Note: call execve, not execle, because we can't call varargs functions with an unknown number of args
    static orig_execve_func_type execve_func = NULL;
    if (execve_func == NULL) {
        execve_func = (orig_execve_func_type)dlsym(RTLD_NEXT, "execve");
    }

    // count args
    int argc = 1;
    va_list args_list;
    va_start(args_list, arg0);
    while (va_arg(args_list, char *) != NULL) argc += 1;
    va_end(args_list);

    // extract args
    const char **argv_buffer = malloc(sizeof(char *) * (argc + 1));
    va_start(args_list, arg0);
    argv_buffer[0] = arg0;
    argc = 1;
    char *arg = NULL;
    while ((arg = va_arg(args_list, char *)) != NULL) {
        argv_buffer[argc++] = arg;
    }
    char * const* env = va_arg(args_list, char * const*);
    va_end(args_list);
    argv_buffer[argc] = NULL;

    int result = execve_func(new_path, (char * const*)argv_buffer, env);
    free(argv_buffer); // We ONLY reach this if exec fails, so we need to clean up
    return result;
}
#endif // DISABLE_EXEC


#ifndef DISABLE_RENAME
typedef int (*orig_rename_func_type)(const char *oldpath, const char *newpath);
int rename(const char *oldpath, const char *newpath)
{
    debug_fprintf(stderr, "rename(%s, %s) called\n", oldpath, newpath);

    char buffer[MAX_PATH], buffer2[MAX_PATH];
    const char *new_oldpath = fix_path("rename-old", oldpath, buffer, sizeof buffer);
    const char *new_newpath = fix_path("rename-new", newpath, buffer2, sizeof buffer2);

    static orig_rename_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_rename_func_type)dlsym(RTLD_NEXT, "rename");
    }

    return orig_func(new_oldpath, new_newpath);
}

typedef int (*orig_renameat_func_type)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    debug_fprintf(stderr, "renameat(%s, %s) called\n", oldpath, newpath);

    char buffer[MAX_PATH], buffer2[MAX_PATH];
    const char *new_oldpath = fix_path("renameat-old", oldpath, buffer, sizeof buffer);
    const char *new_newpath = fix_path("renameat-new", newpath, buffer2, sizeof buffer2);

    static orig_renameat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_renameat_func_type)dlsym(RTLD_NEXT, "renameat");
    }

    return orig_func(olddirfd, new_oldpath, newdirfd, new_newpath);
}

typedef int (*orig_renameat2_func_type)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
    debug_fprintf(stderr, "renameat2(%s, %s) called\n", oldpath, newpath);

    char buffer[MAX_PATH], buffer2[MAX_PATH];
    const char *new_oldpath = fix_path("renameat2-old", oldpath, buffer, sizeof buffer);
    const char *new_newpath = fix_path("renameat2-new", newpath, buffer2, sizeof buffer2);

    static orig_renameat2_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_renameat2_func_type)dlsym(RTLD_NEXT, "renameat2");
    }

    return orig_func(olddirfd, new_oldpath, newdirfd, new_newpath, flags);
}
#endif // DISABLE_RENAME


#ifndef DISABLE_HANDLE
typedef int (*orig_name_to_handle_at_func_type)(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags)
{
    debug_fprintf(stderr, "name_to_handle_at(%s) called\n", pathname);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("name_to_handle_at", pathname, buffer, sizeof buffer);
    static orig_name_to_handle_at_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_name_to_handle_at_func_type)dlsym(RTLD_NEXT, "name_to_handle_at");
    }
    return orig_func(dirfd, new_path, handle, mount_id, flags);
}

typedef int (*orig_open_by_handle_at_func_type)(int mount_fd, struct file_handle *handle, int flags);
// open_by_handle_at does not take a path; no mapping needed, but keep for completeness
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)
{
    static orig_open_by_handle_at_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_open_by_handle_at_func_type)dlsym(RTLD_NEXT, "open_by_handle_at");
    }
    return orig_func(mount_fd, handle, flags);
}
#endif // DISABLE_HANDLE


#ifndef DISABLE_OPEN_TREE
typedef int (*orig_open_tree_func_type)(int dfd, const char *filename, unsigned int flags);
int open_tree(int dfd, const char *filename, unsigned int flags)
{
    debug_fprintf(stderr, "open_tree(%s) called\n", filename);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("open_tree", filename, buffer, sizeof buffer);
    static orig_open_tree_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_open_tree_func_type)dlsym(RTLD_NEXT, "open_tree");
    }
    return orig_func(dfd, new_path, flags);
}
#endif // DISABLE_OPEN_TREE


#ifndef DISABLE_MOVE_MOUNT
typedef int (*orig_move_mount_func_type)(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags);
int move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags)
{
    debug_fprintf(stderr, "move_mount(%s -> %s) called\n", from_pathname, to_pathname);
    char buf1[MAX_PATH], buf2[MAX_PATH];
    const char *new_from = fix_path("move_mount-from", from_pathname, buf1, sizeof buf1);
    const char *new_to = fix_path("move_mount-to", to_pathname, buf2, sizeof buf2);
    static orig_move_mount_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_move_mount_func_type)dlsym(RTLD_NEXT, "move_mount");
    }
    return orig_func(from_dfd, new_from, to_dfd, new_to, flags);
}
#endif // DISABLE_MOVE_MOUNT


#ifndef DISABLE_MOUNT_SETATTR
typedef int (*orig_mount_setattr_func_type)(int dfd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size);
int mount_setattr(int dfd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size)
{
    debug_fprintf(stderr, "mount_setattr(%s) called\n", path);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("mount_setattr", path, buffer, sizeof buffer);
    static orig_mount_setattr_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_mount_setattr_func_type)dlsym(RTLD_NEXT, "mount_setattr");
    }
    return orig_func(dfd, new_path, flags, attr, size);
}
#endif // DISABLE_MOUNT_SETATTR


#ifdef __GLIBC__
#ifndef DISABLE_STATMOUNT
typedef int (*orig_statmount_func_type)(int dirfd, const char *pathname, struct statmount *buf, size_t bufsize, unsigned int flags);
int statmount(int dirfd, const char *pathname, struct statmount *buf, size_t bufsize, unsigned int flags)
{
    debug_fprintf(stderr, "statmount(%s) called\n", pathname);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("statmount", pathname, buffer, sizeof buffer);
    static orig_statmount_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_statmount_func_type)dlsym(RTLD_NEXT, "statmount");
    }
    return orig_func(dirfd, new_path, buf, bufsize, flags);
}
#endif // DISABLE_STATMOUNT
#endif // __GLIBC__


#ifndef DISABLE_INOTIFY
typedef int (*orig_inotify_add_watch_func_type)(int fd, const char *pathname, uint32_t mask);
int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
    debug_fprintf(stderr, "inotify_add_watch(%s) called\n", pathname);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("inotify_add_watch", pathname, buffer, sizeof buffer);
    static orig_inotify_add_watch_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_inotify_add_watch_func_type)dlsym(RTLD_NEXT, "inotify_add_watch");
    }
    return orig_func(fd, new_path, mask);
}
#endif // DISABLE_INOTIFY


#ifndef DISABLE_FANOTIFY
#ifdef __GLIBC__
typedef int (*orig_fanotify_mark_func_type)(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname);
int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname)
#else
typedef int (*orig_fanotify_mark_func_type)(int fanotify_fd, unsigned int flags, unsigned long long mask, int dirfd, const char *pathname);
int fanotify_mark(int fanotify_fd, unsigned int flags, unsigned long long mask, int dirfd, const char *pathname)
#endif
{
    debug_fprintf(stderr, "fanotify_mark(%s) called\n", pathname);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("fanotify_mark", pathname, buffer, sizeof buffer);
    static orig_fanotify_mark_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_fanotify_mark_func_type)dlsym(RTLD_NEXT, "fanotify_mark");
    }
    return orig_func(fanotify_fd, flags, mask, dirfd, new_path);
}
#endif // DISABLE_FANOTIFY


#ifndef DISABLE_PIVOT_ROOT
typedef int (*orig_pivot_root_func_type)(const char *new_root, const char *put_old);
int pivot_root(const char *new_root, const char *put_old)
{
    debug_fprintf(stderr, "pivot_root(%s, %s) called\n", new_root, put_old);
    char buf1[MAX_PATH], buf2[MAX_PATH];
    const char *mapped_new = fix_path("pivot_root-new", new_root, buf1, sizeof buf1);
    const char *mapped_old = fix_path("pivot_root-old", put_old, buf2, sizeof buf2);
    static orig_pivot_root_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_pivot_root_func_type)dlsym(RTLD_NEXT, "pivot_root");
    }
    return orig_func(mapped_new, mapped_old);
}
#endif // DISABLE_PIVOT_ROOT
#ifndef DISABLE_LINK
typedef int (*orig_link_func_type)(const char *oldpath, const char *newpath);
int link(const char *oldpath, const char *newpath)
{
    debug_fprintf(stderr, "link(%s, %s) called\n", oldpath, newpath);

    char buffer[MAX_PATH], buffer2[MAX_PATH];
    const char *new_oldpath = fix_path("link-old", oldpath, buffer, sizeof buffer);
    const char *new_newpath = fix_path("link-new", newpath, buffer2, sizeof buffer2);

    static orig_link_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_link_func_type)dlsym(RTLD_NEXT, "link");
    }

    return orig_func(new_oldpath, new_newpath);
}

typedef int (*orig_linkat_func_type)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    debug_fprintf(stderr, "linkat(%s, %s) called\n", oldpath, newpath);

    char buffer[MAX_PATH], buffer2[MAX_PATH];
    const char *new_oldpath = fix_path("linkat-old", oldpath, buffer, sizeof buffer);
    const char *new_newpath = fix_path("linkat-new", newpath, buffer2, sizeof buffer2);

    static orig_linkat_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_linkat_func_type)dlsym(RTLD_NEXT, "linkat");
    }

    return orig_func(olddirfd, new_oldpath, newdirfd, new_newpath, flags);
}

#endif // DISABLE_LINK


#ifndef DISABLE_SCANDIR
typedef int (*scandir_filter_t)(const struct dirent *);
typedef int (*scandir_compar_t)(const struct dirent **, const struct dirent **);
typedef int (*scandir64_filter_t)(const struct dirent64 *);
typedef int (*scandir64_compar_t)(const struct dirent64 **, const struct dirent64 **);
OVERRIDE_FUNCTION(4, 1, int, scandir, const char *, dirp, struct dirent ***, namelist, scandir_filter_t, filter, scandir_compar_t, compar)
OVERRIDE_FUNCTION(5, 2, int, scandirat, int, dirfd, const char *, dirp, struct dirent ***, namelist, scandir_filter_t, filter, scandir_compar_t, compar)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(4, 1, int, scandir64, const char *, dirp, struct dirent64 ***, namelist, scandir64_filter_t, filter, scandir64_compar_t, compar)
OVERRIDE_FUNCTION(5, 2, int, scandirat64, int, dirfd, const char *, dirp, struct dirent64 ***, namelist, scandir64_filter_t, filter, scandir64_compar_t, compar)
#endif
#endif // DISABLE_SCANDIR


#ifndef DISABLE_CREAT
OVERRIDE_FUNCTION(2, 1, int, creat, const char *, pathname, mode_t, mode)
#endif // DISABLE_CREAT


#ifdef __GLIBC__
#ifndef DISABLE_STAT
OVERRIDE_FUNCTION(2, 1, int, stat64, const char *, path, struct stat64 *, buf)
OVERRIDE_FUNCTION(2, 1, int, lstat64, const char *, path, struct stat64 *, buf)
#endif // DISABLE_STAT
#endif // __GLIBC__


#ifndef DISABLE_STATX
OVERRIDE_FUNCTION(5, 2, int, statx, int, dirfd, const char *, pathname, int, flags, unsigned int, mask, struct statx *, statxbuf)
#endif // DISABLE_STATX


#ifndef DISABLE_MOUNT
OVERRIDE_FUNCTION(2, 1, FILE *, setmntent, const char *, filename, const char *, type)
#endif // DISABLE_MOUNT


#ifndef DISABLE_GLOB
typedef int (*glob_errfunc_t)(const char *, int);
OVERRIDE_FUNCTION(4, 1, int, glob, const char *, pattern, int, flags, glob_errfunc_t, errfunc, glob_t *, pglob)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(4, 1, int, glob64, const char *, pattern, int, flags, glob_errfunc_t, errfunc, glob64_t *, pglob)
#endif
#endif // DISABLE_GLOB


#ifndef DISABLE_SPAWN
typedef int (*orig_posix_spawn_func_type)(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char * const argv[], char * const envp[]);
int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char * const argv[], char * const envp[])
{
    debug_fprintf(stderr, "posix_spawn(%s) called\n", path);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("posix_spawn", path, buffer, sizeof buffer);
    static orig_posix_spawn_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_posix_spawn_func_type)dlsym(RTLD_NEXT, "posix_spawn");
    }
    return orig_func(pid, new_path, file_actions, attrp, argv, envp);
}

typedef int (*orig_posix_spawnp_func_type)(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char * const argv[], char * const envp[]);
int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char * const argv[], char * const envp[])
{
    debug_fprintf(stderr, "posix_spawnp(%s) called\n", file);
    char buffer[MAX_PATH];
    const char *new_path = fix_path("posix_spawnp", file, buffer, sizeof buffer);
    static orig_posix_spawnp_func_type orig_func = NULL;
    if (orig_func == NULL) {
        orig_func = (orig_posix_spawnp_func_type)dlsym(RTLD_NEXT, "posix_spawnp");
    }
    return orig_func(pid, new_path, file_actions, attrp, argv, envp);
}
#endif // DISABLE_SPAWN


#ifndef DISABLE_DLOPEN
OVERRIDE_FUNCTION(2, 1, void *, dlopen, const char *, filename, int, flag)
#ifdef __GLIBC__
OVERRIDE_FUNCTION(3, 2, void *, dlmopen, Lmid_t, lmid, const char *, filename, int, flag)
#endif
#endif // DISABLE_DLOPEN


#ifndef DISABLE_CREAT
OVERRIDE_FUNCTION(1, 1, int, acct, const char *, filename)
#endif // DISABLE_CREAT
