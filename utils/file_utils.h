#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string.h>

static inline int is_txt_file(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) return 0;
    return (_stricmp(filename + len - 4, ".txt") == 0);
}

static inline const char* get_basename(const char *path) {
    const char *base = path;
    const char *p1 = strrchr(path, '/');
    const char *p2 = strrchr(path, '\\');
    if (p1 && p1 + 1 > base) base = p1 + 1;
    if (p2 && p2 + 1 > base) base = p2 + 1;
    return base;
}

#endif // FILE_UTILS_H
