#include "message_router.h"

#include "../crypto/cipher.h"
#include "connection_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Frame format:
 *
 * 4 bytes  -> payload length (network byte order)
 * N bytes  -> encrypted payload
 */

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
    if (length > UINT32_MAX)
        return 0;

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

    int result =
        send_all(
            socket,
            (unsigned char *)&network_length,
            sizeof(network_length)
        );

    if (result)
    {
        result =
            send_all(
                socket,
                encrypted,
                length
            );
    }

    free(encrypted);

    return result;
}

int send_plain_response(
    SOCKET socket,
    const char *message)
{
    uint32_t length =
        (uint32_t)strlen(message);

    uint32_t network_length =
        htonl(length);

    if (!send_all(
        socket,
        (unsigned char *)&network_length,
        sizeof(network_length)))
    {
        return 0;
    }

    return send_all(
        socket,
        (const unsigned char *)message,
        length
    );
}

int send_encrypted_error(
    SOCKET socket,
    const char *key,
    const char *message)
{
    char response[BUFFER_SIZE];

    _snprintf_s(
        response,
        sizeof(response),
        _TRUNCATE,
        "ERROR %s",
        message
    );

    return send_encrypted_frame(
        socket,
        key,
        (unsigned char *)response,
        strlen(response)
    );
}

int route_message(
    SOCKET sender_socket,
    const char *target_username,
    const unsigned char *plaintext,
    size_t plaintext_length)
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
     * Construct:
     *
     * FROM sender: message
     */

    size_t prefix_length =
        strlen("FROM ") +
        strlen(sender_username) +
        strlen(": ");

    size_t output_length =
        prefix_length +
        plaintext_length;

    if (output_length >= BUFFER_SIZE)
    {
        send_encrypted_error(
            sender_socket,
            sender_key,
            "message too large"
        );

        return 0;
    }

    unsigned char *output =
        (unsigned char *)malloc(output_length + 1);

    if (output == NULL)
        return 0;

    int written = _snprintf_s(
        (char *)output,
        output_length + 1,
        _TRUNCATE,
        "FROM %s: ",
        sender_username
    );

    if (written < 0)
    {
        free(output);
        return 0;
    }

    memcpy(
        output + written,
        plaintext,
        plaintext_length
    );

    int result =
        send_encrypted_frame(
            receiver_socket,
            receiver_key,
            output,
            output_length
        );

    free(output);

    return result;
}