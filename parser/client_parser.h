#ifndef CLIENT_PARSER_H
#define CLIENT_PARSER_H

#include <string.h>

static inline int parse_sendfile_command(const char *input, char *target, size_t target_size, char *filepath, size_t filepath_size) {
    const char *prefix = "SENDFILE TO ";
    size_t prefix_len = strlen(prefix);
    if (_strnicmp(input, prefix, prefix_len) != 0) {
        return 0;
    }

    const char *p = input + prefix_len;
    while (*p == ' ') p++;
    if (*p == '\0') return 0;

    const char *colon = strchr(p, ':');
    if (colon != NULL) {
        size_t target_len = colon - p;
        if (target_len >= target_size || target_len == 0) return 0;
        strncpy(target, p, target_len);
        target[target_len] = '\0';

        while (target_len > 0 && target[target_len - 1] == ' ') {
            target[--target_len] = '\0';
        }

        const char *f = colon + 1;
        while (*f == ' ') f++;
        if (*f == '\0') return 0;

        size_t f_len = strlen(f);
        if (f_len >= filepath_size) return 0;
        strncpy(filepath, f, filepath_size);
        filepath[filepath_size - 1] = '\0';

        while (f_len > 0 && (filepath[f_len - 1] == ' ' || filepath[f_len - 1] == '\r' || filepath[f_len - 1] == '\n')) {
            filepath[--f_len] = '\0';
        }
        return (target_len > 0 && f_len > 0);
    } else {
        const char *space = strchr(p, ' ');
        if (space == NULL) return 0;

        size_t target_len = space - p;
        if (target_len >= target_size || target_len == 0) return 0;
        strncpy(target, p, target_len);
        target[target_len] = '\0';

        const char *f = space + 1;
        while (*f == ' ') f++;
        if (*f == '\0') return 0;

        size_t f_len = strlen(f);
        if (f_len >= filepath_size) return 0;
        strncpy(filepath, f, filepath_size);
        filepath[filepath_size - 1] = '\0';

        while (f_len > 0 && (filepath[f_len - 1] == ' ' || filepath[f_len - 1] == '\r' || filepath[f_len - 1] == '\n')) {
            filepath[--f_len] = '\0';
        }
        return (target_len > 0 && f_len > 0);
    }
}

#endif // CLIENT_PARSER_H
