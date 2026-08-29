#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <winsock2.h>
#include <stddef.h>

int route_file(
    SOCKET sender_socket,
    const char *target_username,
    const char *filename,
    const unsigned char *file_content,
    size_t file_size
);

int is_valid_text_filename(const char *filename);

#endif