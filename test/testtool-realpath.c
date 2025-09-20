#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        return 1;
    }
    
    const char *path = argv[1];
    char resolved_path[PATH_MAX];
    
    // Test realpath with buffer
    char *result = realpath(path, resolved_path);
    if (result == NULL) {
        perror("realpath failed");
        return 1;
    }
    
    printf("realpath with buffer: %s\n", result);
    
    // Test realpath without buffer (allocates memory)
    char *result2 = realpath(path, NULL);
    if (result2 == NULL) {
        perror("realpath(NULL) failed");
        return 1;
    }
    
    printf("realpath with NULL: %s\n", result2);
    free(result2);
    
    return 0;
}
