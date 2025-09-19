#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path> <op> [name] [value]\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    const char *op = argv[2];
    if (strcmp(op, "set") == 0) {
        if (argc < 5) { fprintf(stderr, "set requires name and value\n"); return 2; }
        const char *name = argv[3];
        const char *value = argv[4];
        if (setxattr(path, name, value, strlen(value), 0) == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP) { puts("skip"); return 0; }
            die("setxattr");
        }
        puts("ok");
        return 0;
    } else if (strcmp(op, "get") == 0) {
        if (argc < 4) { fprintf(stderr, "get requires name\n"); return 2; }
        const char *name = argv[3];
        char buf[4096];
        ssize_t n = getxattr(path, name, buf, sizeof buf);
        if (n == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP) { puts("skip"); return 0; }
            die("getxattr");
        }
        fwrite(buf, 1, (size_t)n, stdout);
        putchar('\n');
        return 0;
    } else if (strcmp(op, "list") == 0) {
        char buf[4096];
        ssize_t n = listxattr(path, buf, sizeof buf);
        if (n == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP) { puts("skip"); return 0; }
            die("listxattr");
        }
        fwrite(buf, 1, (size_t)n, stdout);
        return 0;
    } else if (strcmp(op, "remove") == 0) {
        if (argc < 4) { fprintf(stderr, "remove requires name\n"); return 2; }
        const char *name = argv[3];
        if (removexattr(path, name) == -1) {
            if (errno == ENODATA
#ifdef ENOATTR
                || errno == ENOATTR
#endif
            ) { puts("ok"); return 0; }
            if (errno == ENOTSUP || errno == EOPNOTSUPP) { puts("skip"); return 0; }
            die("removexattr");
        }
        puts("ok");
        return 0;
    } else if (strcmp(op, "lset") == 0) {
        if (argc < 5) { fprintf(stderr, "lset requires name and value\n"); return 2; }
        const char *name = argv[3];
        const char *value = argv[4];
        if (lsetxattr(path, name, value, strlen(value), 0) == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) { puts("skip"); return 0; }
            die("lsetxattr");
        }
        puts("ok");
        return 0;
    } else if (strcmp(op, "lget") == 0) {
        if (argc < 4) { fprintf(stderr, "lget requires name\n"); return 2; }
        const char *name = argv[3];
        char buf[4096];
        ssize_t n = lgetxattr(path, name, buf, sizeof buf);
        if (n == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) { puts("skip"); return 0; }
            die("lgetxattr");
        }
        fwrite(buf, 1, (size_t)n, stdout);
        putchar('\n');
        return 0;
    } else if (strcmp(op, "llist") == 0) {
        char buf[4096];
        ssize_t n = llistxattr(path, buf, sizeof buf);
        if (n == -1) {
            if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) { puts("skip"); return 0; }
            die("llistxattr");
        }
        fwrite(buf, 1, (size_t)n, stdout);
        return 0;
    } else if (strcmp(op, "lremove") == 0) {
        if (argc < 4) { fprintf(stderr, "lremove requires name\n"); return 2; }
        const char *name = argv[3];
        if (lremovexattr(path, name) == -1) {
            if (errno == ENODATA
#ifdef ENOATTR
                || errno == ENOATTR
#endif
            ) { puts("ok"); return 0; }
            if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM) { puts("skip"); return 0; }
            die("lremovexattr");
        }
        puts("ok");
        return 0;
    }
    fprintf(stderr, "unknown op %s\n", op);
    return 2;
}

