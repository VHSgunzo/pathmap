#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __GLIBC__

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 1;
    }
    
    const char *path = argv[1];
    
    // Test canonicalize_file_name
    char *result = canonicalize_file_name(path);
    if (result == NULL) {
        perror("canonicalize_file_name failed");
        return 1;
    }
    
    printf("canonicalize_file_name: %s\n", result);
    free(result);
    
    return 0;
}

#else
// For non-GLIBC systems, just print a message
int main(int argc, char *argv[]) {
    printf("canonicalize_file_name: not available on this system\n");
    return 0;
}
#endif
