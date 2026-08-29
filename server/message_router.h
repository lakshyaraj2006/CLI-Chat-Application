#ifndef MESSAGE_ROUTER_H
#define MESSAGE_ROUTER_H

#include <winsock2.h>
#include <stddef.h>

int route_message(
    SOCKET sender_socket,
    const char *target_username,
    const unsigned char *plaintext,
    size_t plaintext_length
);

int send_encrypted_error(
    SOCKET socket,
    const char *key,
    const char *message
);

int send_plain_response(
    SOCKET socket,
    const char *message
);

#endif