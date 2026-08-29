#include <winsock2.h>
#include <windows.h>
#include <process.h>

#include <stdio.h>
#include <stdlib.h>

#include "connection_manager.h"
#include "client_handler.h"
#include "message_router.h"

#include "../config/constants.h"

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char *argv[])
{
    WSADATA wsaData;

    /*
     * Initialize Winsock
     */
    int result =
        WSAStartup(
            MAKEWORD(2, 2),
            &wsaData
        );

    if (result != 0)
    {
        printf(
            "WSAStartup failed: %d\n",
            result
        );

        return 1;
    }

    int port = PORT;

    if (argc >= 2)
    {
        port = atoi(argv[1]);

        if (port <= 0 || port > 65535)
        {
            printf(
                "Invalid port number.\n"
            );

            WSACleanup();
            return 1;
        }
    }

    /*
     * Create server socket
     */
    SOCKET server_socket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );

    if (server_socket == INVALID_SOCKET)
    {
        printf(
            "Socket creation failed: %d\n",
            WSAGetLastError()
        );

        WSACleanup();
        return 1;
    }

    /*
     * Allow address reuse
     */
    int opt = 1;

    setsockopt(
        server_socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        (const char *)&opt,
        sizeof(opt)
    );

    /*
     * Server address
     */
    struct sockaddr_in server_address;

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family =
        AF_INET;

    server_address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    server_address.sin_port =
        htons((u_short)port);

    /*
     * Bind
     */
    if (bind(
        server_socket,
        (struct sockaddr *)&server_address,
        sizeof(server_address)
    ) == SOCKET_ERROR)
    {
        printf(
            "Bind failed: %d\n",
            WSAGetLastError()
        );

        closesocket(server_socket);
        WSACleanup();

        return 1;
    }

    /*
     * Listen
     */
    if (listen(
        server_socket,
        SOMAXCONN
    ) == SOCKET_ERROR)
    {
        printf(
            "Listen failed: %d\n",
            WSAGetLastError()
        );

        closesocket(server_socket);
        WSACleanup();

        return 1;
    }

    connection_manager_init();

    printf(
        "=====================================\n"
        "       SECURE CHAT SERVER\n"
        "=====================================\n"
    );

    printf(
        "[SERVER] Listening on port %d\n",
        port
    );

    while (1)
    {
        struct sockaddr_in client_address;
        int address_length =
            sizeof(client_address);

        SOCKET client_socket =
            accept(
                server_socket,
                (struct sockaddr *)&client_address,
                &address_length
            );

        if (client_socket == INVALID_SOCKET)
        {
            printf(
                "Accept failed: %d\n",
                WSAGetLastError()
            );

            continue;
        }

        /*
         * Add client to connection manager
         */
        if (!add_client(
            client_socket,
            client_address
        ))
        {
            const char *error =
                "ERROR server full";

            send_plain_response(
                client_socket,
                error
            );

            closesocket(client_socket);

            continue;
        }

        /*
         * Allocate thread arguments
         */
        ClientThreadArgs *args =
            (ClientThreadArgs *)
                malloc(sizeof(ClientThreadArgs));

        if (args == NULL)
        {
            printf(
                "[SERVER] Memory allocation failed.\n"
            );

            remove_client(client_socket);
            closesocket(client_socket);

            continue;
        }

        args->socket =
            client_socket;

        args->address =
            client_address;

        /*
         * One thread per connected client.
         *
         * This satisfies the assignment's
         * concurrency requirement.
         */
        uintptr_t thread =
            _beginthreadex(
                NULL,
                0,
                client_handler,
                args,
                0,
                NULL
            );

        if (thread == 0)
        {
            printf(
                "[SERVER] Could not create client thread.\n"
            );

            free(args);

            remove_client(client_socket);
            closesocket(client_socket);

            continue;
        }

        /*
         * The server does not need to wait
         * for individual client threads.
         */
        CloseHandle(
            (HANDLE)thread
        );
    }

    connection_manager_cleanup();

    closesocket(server_socket);

    WSACleanup();

    return 0;
}