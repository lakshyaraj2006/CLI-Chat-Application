#include "client_handler.h"

#include "connection_manager.h"
#include "message_router.h"
#include "file_handler.h"

#include "../parser/server_parser.h"
#include "../crypto/cipher.h"
#include "../config/constants.h"

#include <winsock2.h>
#include <windows.h>
#include <process.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* =========================================================
   HELPER: send all bytes
   ========================================================= */

static int send_all(
    SOCKET socket,
    const unsigned char *buffer,
    size_t length)
{
    size_t total_sent = 0;

    while (total_sent < length)
    {
        int sent = send(
            socket,
            (const char *)buffer + total_sent,
            (int)(length - total_sent),
            0
        );

        if (sent == SOCKET_ERROR || sent == 0)
        {
            return 0;
        }

        total_sent += (size_t)sent;
    }

    return 1;
}

/* =========================================================
   HELPER: receive exactly length bytes
   ========================================================= */

static int recv_all(
    SOCKET socket,
    unsigned char *buffer,
    size_t length)
{
    size_t total_received = 0;

    while (total_received < length)
    {
        int received = recv(
            socket,
            (char *)buffer + total_received,
            (int)(length - total_received),
            0
        );

        if (received == 0)
        {
            /* Client closed connection */
            return 0;
        }

        if (received == SOCKET_ERROR)
        {
            return 0;
        }

        total_received += (size_t)received;
    }

    return 1;
}

/* =========================================================
   HELPER: receive one length-prefixed frame

   Format:
   [4 bytes length][payload]
   ========================================================= */

static int receive_frame(
    SOCKET socket,
    unsigned char **payload,
    size_t *payload_length)
{
    uint32_t network_length;

    if (!recv_all(
        socket,
        (unsigned char *)&network_length,
        sizeof(network_length)))
    {
        return 0;
    }

    uint32_t length = ntohl(network_length);

    /*
     * Reject empty or excessively large frames.
     */
    if (length == 0 || length > BUFFER_SIZE)
    {
        return -1;
    }

    unsigned char *buffer =
        (unsigned char *)malloc((size_t)length + 1);

    if (buffer == NULL)
    {
        return -1;
    }

    if (!recv_all(
        socket,
        buffer,
        length))
    {
        free(buffer);
        return 0;
    }

    /*
     * Extra byte is only for convenient string handling.
     * It is NOT part of the network payload.
     */
    buffer[length] = '\0';

    *payload = buffer;
    *payload_length = length;

    return 1;
}

/* =========================================================
   HELPER: send encrypted length-prefixed response
   ========================================================= */

static int send_encrypted_response(
    SOCKET socket,
    const char *key,
    const unsigned char *message,
    size_t message_length)
{
    if (message_length > BUFFER_SIZE)
    {
        return 0;
    }

    unsigned char *encrypted =
        (unsigned char *)malloc(message_length);

    if (encrypted == NULL)
    {
        return 0;
    }

    memcpy(
        encrypted,
        message,
        message_length
    );

    /*
     * Encrypt using this client's key.
     */
    repeatedXOR(
        encrypted,
        (int)message_length,
        (unsigned char *)key
    );

    uint32_t network_length =
        htonl((uint32_t)message_length);

    /*
     * First send 4-byte length.
     */
    if (!send_all(
        socket,
        (unsigned char *)&network_length,
        sizeof(network_length)))
    {
        free(encrypted);
        return 0;
    }

    /*
     * Then send encrypted payload.
     */
    if (!send_all(
        socket,
        encrypted,
        message_length))
    {
        free(encrypted);
        return 0;
    }

    free(encrypted);

    return 1;
}

/* =========================================================
   HANDLE REGISTER
   ========================================================= */

static void handle_register(
    SOCKET socket,
    unsigned char *payload)
{
    /*
     * register_parser() returns RegisterData directly.
     */
    RegisterData data =
        register_parser((char *)payload);

    if (!data.valid)
    {
        /*
         * Registration is the bootstrap stage.
         * The client has not yet established a
         * server-known key for encrypted replies.
         *
         * Therefore the registration error/response
         * is sent as a plain length-prefixed frame.
         */
        const char *response =
            "ERROR invalid command format";

        send_plain_response(
            socket,
            response
        );

        return;
    }

    /*
     * Validate username length.
     *
     * RegisterData.username has size 9,
     * so maximum username length is 8.
     */
    if (strlen(data.username) == 0 ||
        strlen(data.username) > 8)
    {
        const char *response =
            "ERROR invalid username";

        send_plain_response(
            socket,
            response
        );

        return;
    }

    /*
     * Validate 6-character key.
     */
    if (strlen(data.key) != KEY_LENGTH)
    {
        const char *response =
            "ERROR invalid key";

        send_plain_response(
            socket,
            response
        );

        return;
    }

    /*
     * Store username and key.
     */
    if (!register_client(
        socket,
        data.username,
        data.key))
    {
        char response[128];

        _snprintf_s(
            response,
            sizeof(response),
            _TRUNCATE,
            "ERROR username %s already taken",
            data.username
        );

        send_plain_response(
            socket,
            response
        );

        return;
    }

    /*
     * Registration successful.
     */
    char response[128];

    _snprintf_s(
        response,
        sizeof(response),
        _TRUNCATE,
        "REGISTERED %s",
        data.username
    );

    send_plain_response(
        socket,
        response
    );

    printf(
        "[SERVER] Registered user: %s\n",
        data.username
    );
}

/* =========================================================
   HANDLE SEND
   ========================================================= */

static void handle_send(
    SOCKET socket,
    unsigned char *payload,
    size_t payload_length)
{
    char username[9];
    char key[7];

    /*
     * Get sender's username and key.
     */
    if (!get_client_info_by_socket(
        socket,
        username,
        sizeof(username),
        key,
        sizeof(key)))
    {
        return;
    }

    /*
     * VERY IMPORTANT:
     *
     * message_parser() uses strtok(), which modifies
     * the string.
     *
     * Therefore parse a COPY of the received payload.
     */
    if (payload_length >= BUFFER_SIZE)
    {
        send_encrypted_error(
            socket,
            key,
            "message too large"
        );

        return;
    }

    char command_copy[BUFFER_SIZE];

    memcpy(
        command_copy,
        payload,
        payload_length
    );

    command_copy[payload_length] = '\0';

    MessageData message =
        message_parser(command_copy);

    if (!message.valid)
    {
        send_encrypted_error(
            socket,
            key,
            "invalid command format"
        );

        return;
    }

    /*
     * Route to target client.
     *
     * route_message() will:
     * 1. find target
     * 2. encrypt using target's key
     * 3. send to target
     */
    if (!route_message(
        socket,
        message.target_user,
        (unsigned char *)message.message,
        strlen(message.message)))
    {
        /*
         * route_message() already sends an appropriate
         * error in most failure cases.
         */
        printf(
            "[SERVER] Failed to route message from %s\n",
            username
        );
    }
}

/* =========================================================
   HANDLE QUIT
   ========================================================= */

static void handle_quit(
    SOCKET socket)
{
    char username[9];
    char key[7];

    if (!get_client_info_by_socket(
        socket,
        username,
        sizeof(username),
        key,
        sizeof(key)))
    {
        return;
    }

    char response[64];

    _snprintf_s(
        response,
        sizeof(response),
        _TRUNCATE,
        "GOODBYE %s",
        username
    );

    /*
     * QUIT response is encrypted.
     */
    send_encrypted_response(
        socket,
        key,
        (unsigned char *)response,
        strlen(response)
    );

    printf(
        "[SERVER] User quitting: %s\n",
        username
    );
}

/* =========================================================
   HANDLE LIST
   ========================================================= */

static void handle_list(
    SOCKET socket)
{
    char username[9];
    char key[7];

    if (!get_client_info_by_socket(
        socket,
        username,
        sizeof(username),
        key,
        sizeof(key)))
    {
        return;
    }

    char users[BUFFER_SIZE];

    get_online_users(
        users,
        sizeof(users)
    );

    char response[BUFFER_SIZE];

    if (users[0] == '\0')
    {
        _snprintf_s(
            response,
            sizeof(response),
            _TRUNCATE,
            "ONLINE"
        );
    }
    else
    {
        _snprintf_s(
            response,
            sizeof(response),
            _TRUNCATE,
            "ONLINE %s",
            users
        );
    }

    send_encrypted_response(
        socket,
        key,
        (unsigned char *)response,
        strlen(response)
    );
}

/* =========================================================
   HANDLE SENDFILE
   ========================================================= */

static void handle_sendfile(
    SOCKET socket,
    unsigned char *payload,
    size_t payload_length)
{
    char username[9];
    char key[7];

    if (!get_client_info_by_socket(
        socket,
        username,
        sizeof(username),
        key,
        sizeof(key)))
    {
        return;
    }

    /*
     * Find the first newline.
     *
     * Header:
     *
     * SENDFILE TO <user> <filename> <size>\n
     *
     * Everything after that is file data.
     */
    unsigned char *newline =
        (unsigned char *)memchr(
            payload,
            '\n',
            payload_length
        );

    if (newline == NULL)
    {
        send_encrypted_error(
            socket,
            key,
            "invalid file format"
        );

        return;
    }

    /*
     * Temporarily terminate header.
     */
    *newline = '\0';

    char target[9];
    char filename[260];

    unsigned long long declared_size = 0;

    /*
     * Parse:
     *
     * SENDFILE TO monk notes.txt 142
     */
    int fields = sscanf_s(
        (char *)payload,
        "SENDFILE TO %8s %259s %llu",
        target,
        (unsigned)_countof(target),
        filename,
        (unsigned)_countof(filename),
        &declared_size
    );

    if (fields != 3)
    {
        send_encrypted_error(
            socket,
            key,
            "invalid file format"
        );

        return;
    }

    /*
     * File data begins immediately after '\n'.
     */
    unsigned char *file_data =
        newline + 1;

    size_t header_and_newline =
        (size_t)(file_data - payload);

    size_t actual_size =
        payload_length - header_and_newline;

    /*
     * Validate declared size.
     */
    if (declared_size != actual_size)
    {
        send_encrypted_error(
            socket,
            key,
            "file size mismatch"
        );

        return;
    }

    /*
     * File size limit.
     */
    if (actual_size > MAX_FILE_SIZE)
    {
        send_encrypted_error(
            socket,
            key,
            "file too large"
        );

        return;
    }

    /*
     * Only .txt files are allowed.
     */
    if (!is_valid_text_filename(filename))
    {
        send_encrypted_error(
            socket,
            key,
            "only .txt files are supported"
        );

        return;
    }

    /*
     * Forward file to recipient.
     */
    if (!route_file(
        socket,
        target,
        filename,
        file_data,
        actual_size))
    {
        printf(
            "[SERVER] File routing failed: %s -> %s\n",
            username,
            target
        );
    }
}

/* =========================================================
   MAIN CLIENT THREAD
   ========================================================= */

unsigned __stdcall client_handler(void *arg)
{
    /*
     * Copy thread arguments locally.
     */
    ClientThreadArgs *args =
        (ClientThreadArgs *)arg;

    if (args == NULL)
    {
        return 0;
    }

    SOCKET socket =
        args->socket;

    struct sockaddr_in address =
        args->address;

    /*
     * The allocated argument is no longer needed.
     */
    free(args);

    printf(
        "[SERVER] Client connected: %s:%d\n",
        inet_ntoa(address.sin_addr),
        ntohs(address.sin_port)
    );

    while (1)
    {
        unsigned char *frame = NULL;
        size_t frame_length = 0;

        /*
         * Receive one complete frame.
         */
        int receive_result =
            receive_frame(
                socket,
                &frame,
                &frame_length
            );

        /*
         * Client disconnected normally or abruptly.
         */
        if (receive_result == 0)
        {
            printf(
                "[SERVER] Client disconnected.\n"
            );

            break;
        }

        /*
         * Invalid/oversized frame.
         */
        if (receive_result < 0)
        {
            char username[9];
            char key[7];

            if (get_client_info_by_socket(
                socket,
                username,
                sizeof(username),
                key,
                sizeof(key)))
            {
                send_encrypted_error(
                    socket,
                    key,
                    "invalid or oversized frame"
                );
            }

            free(frame);

            break;
        }

        /*
         * Check whether the client has registered.
         */
        char current_username[9];
        char current_key[7];

        int registered =
            get_client_info_by_socket(
                socket,
                current_username,
                sizeof(current_username),
                current_key,
                sizeof(current_key)
            );

        /* =================================================
           CLIENT NOT YET REGISTERED
           ================================================= */

        if (!registered)
        {
            /*
             * REGISTER is the bootstrap command.
             *
             * It is received before the server has
             * obtained the client's symmetric key.
             *
             * Therefore the REGISTER frame itself is
             * treated as plaintext.
             */
            if (frame_length >= BUFFER_SIZE)
            {
                free(frame);
                continue;
            }

            char register_copy[BUFFER_SIZE];

            memcpy(
                register_copy,
                frame,
                frame_length
            );

            register_copy[frame_length] = '\0';

            /*
             * Only REGISTER is permitted before
             * registration.
             */
            if (strncmp(
                register_copy,
                "REGISTER ",
                9) == 0)
            {
                handle_register(
                    socket,
                    (unsigned char *)register_copy
                );
            }
            else
            {
                const char *response =
                    "ERROR please register first";

                send_plain_response(
                    socket,
                    response
                );
            }

            free(frame);

            continue;
        }

        /* =================================================
           CLIENT IS REGISTERED
           ================================================= */

        /*
         * Decrypt using sender's key.
         */
        repeatedXOR(
            frame,
            (int)frame_length,
            (unsigned char *)current_key
        );

        /*
         * Now frame contains plaintext.
         */
        frame[frame_length] = '\0';

        /*
         * Detect command.
         */

        /* -------------------------------------------------
           SEND TO
           ------------------------------------------------- */

        if (strncmp(
            (char *)frame,
            "SEND TO ",
            8) == 0)
        {
            handle_send(
                socket,
                frame,
                frame_length
            );
        }

        /* -------------------------------------------------
           SENDFILE
           ------------------------------------------------- */

        else if (strncmp(
            (char *)frame,
            "SENDFILE TO ",
            12) == 0)
        {
            handle_sendfile(
                socket,
                frame,
                frame_length
            );
        }

        /* -------------------------------------------------
           QUIT
           ------------------------------------------------- */

        else if (_stricmp(
            (char *)frame,
            "QUIT") == 0)
        {
            handle_quit(socket);

            free(frame);

            break;
        }

        /* -------------------------------------------------
           LIST
           ------------------------------------------------- */

        else if (_stricmp(
            (char *)frame,
            "LIST") == 0)
        {
            handle_list(socket);
        }

        /* -------------------------------------------------
           UNKNOWN COMMAND
           ------------------------------------------------- */

        else
        {
            send_encrypted_error(
                socket,
                current_key,
                "unknown command"
            );
        }

        free(frame);
    }

    /*
     * Get username before removing client.
     */
    char username[9];
    char key[7];

    if (get_client_info_by_socket(
        socket,
        username,
        sizeof(username),
        key,
        sizeof(key)))
    {
        printf(
            "[SERVER] Cleaning up user: %s\n",
            username
        );
    }

    /*
     * Remove client from the server's table.
     */
    remove_client(socket);

    /*
     * Close socket.
     */
    closesocket(socket);

    printf(
        "[SERVER] Client connection closed.\n"
    );

    return 0;
}