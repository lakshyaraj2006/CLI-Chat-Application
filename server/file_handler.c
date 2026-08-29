#include "file_handler.h"

#include "connection_manager.h"
#include "message_router.h"

#include "../config/constants.h"
#include "../crypto/cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int send_all(
    SOCKET socket,
    const unsigned char *data,
    size_t length)
{
    size_t total_sent = 0;

    while (total_sent < length)
    {
        int sent = send(
            socket,
            (const char *)data + total_sent,
            (int)(length - total_sent),
            0
        );

        if (sent == SOCKET_ERROR || sent == 0)
        {
            return 0;
        }

        total_sent += sent;
    }

    return 1;
}

static int send_encrypted_frame(
    SOCKET socket,
    const char *key,
    const unsigned char *plaintext,
    size_t length)
{
    unsigned char *encrypted =
        (unsigned char *)malloc(length);

    if (encrypted == NULL)
        return 0;

    memcpy(encrypted, plaintext, length);

    repeatedXOR(
        encrypted,
        (int)length,
        (unsigned char *)key
    );

    uint32_t network_length =
        htonl((uint32_t)length);

    int result = send_all(
        socket,
        (unsigned char *)&network_length,
        sizeof(network_length)
    );

    if (result)
    {
        result = send_all(
            socket,
            encrypted,
            length
        );
    }

    free(encrypted);

    return result;
}

int is_valid_text_filename(const char *filename)
{
    size_t length = strlen(filename);

    if (length < 4)
        return 0;

    const char *extension =
        filename + length - 4;

    return (
        _stricmp(extension, ".txt") == 0
    );
}

int route_file(
    SOCKET sender_socket,
    const char *target_username,
    const char *filename,
    const unsigned char *file_content,
    size_t file_size)
{
    char sender_username[9];
    char sender_key[7];

    if (!get_client_info_by_socket(
        sender_socket,
        sender_username,
        sizeof(sender_username),
        sender_key,
        sizeof(sender_key)))
    {
        return 0;
    }

    if (file_size > MAX_FILE_SIZE)
    {
        return send_encrypted_error(
            sender_socket,
            sender_key,
            "file too large"
        );
    }

    if (!is_valid_text_filename(filename))
    {
        return send_encrypted_error(
            sender_socket,
            sender_key,
            "only .txt files are supported"
        );
    }

    SOCKET receiver_socket;
    char receiver_key[7];

    if (!get_client_info_by_username(
        target_username,
        &receiver_socket,
        receiver_key,
        sizeof(receiver_key)))
    {
        char error[128];

        _snprintf_s(
            error,
            sizeof(error),
            _TRUNCATE,
            "%s is not online",
            target_username
        );

        return send_encrypted_error(
            sender_socket,
            sender_key,
            error
        );
    }

    /*
     * File frame:
     *
     * RECVFILE FROM <sender> <filename> <size>\n
     * <file bytes>
     */

    char header[512];

    int header_length = _snprintf_s(
        header,
        sizeof(header),
        _TRUNCATE,
        "RECVFILE FROM %s %s %zu\n",
        sender_username,
        filename,
        file_size
    );

    if (header_length < 0)
        return 0;

    size_t total_length =
        (size_t)header_length +
        file_size;

    if (total_length > BUFFER_SIZE)
    {
        return send_encrypted_error(
            sender_socket,
            sender_key,
            "file frame too large"
        );
    }

    unsigned char *frame =
        (unsigned char *)malloc(total_length);

    if (frame == NULL)
        return 0;

    memcpy(
        frame,
        header,
        header_length
    );

    memcpy(
        frame + header_length,
        file_content,
        file_size
    );

    int result = send_encrypted_frame(
        receiver_socket,
        receiver_key,
        frame,
        total_length
    );

    free(frame);

    return result;
}