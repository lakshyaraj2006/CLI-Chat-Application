#include "connection_manager.h"

#include <stdio.h>
#include <string.h>

static ServerClient clients[MAX_CONNECTED_CLIENTS];
static CRITICAL_SECTION connection_lock;

void connection_manager_init(void)
{
    InitializeCriticalSection(&connection_lock);

    memset(clients, 0, sizeof(clients));

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        clients[i].socket = INVALID_SOCKET;
        clients[i].registered = 0;
    }
}

void connection_manager_cleanup(void)
{
    DeleteCriticalSection(&connection_lock);
}

CRITICAL_SECTION *get_connection_lock(void)
{
    return &connection_lock;
}

int add_client(SOCKET socket, struct sockaddr_in address)
{
    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket == INVALID_SOCKET)
        {
            clients[i].socket = socket;
            clients[i].address = address;
            clients[i].registered = 0;
            clients[i].username[0] = '\0';
            clients[i].key[0] = '\0';

            LeaveCriticalSection(&connection_lock);
            return 1;
        }
    }

    LeaveCriticalSection(&connection_lock);
    return 0;
}

void remove_client(SOCKET socket)
{
    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket == socket)
        {
            clients[i].socket = INVALID_SOCKET;
            clients[i].registered = 0;
            clients[i].username[0] = '\0';
            clients[i].key[0] = '\0';
            memset(&clients[i].address, 0, sizeof(clients[i].address));
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);
}

int is_username_taken(const char *username)
{
    int found = 0;

    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket != INVALID_SOCKET &&
            clients[i].registered &&
            _stricmp(clients[i].username, username) == 0)
        {
            found = 1;
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);

    return found;
}

int register_client(SOCKET socket, const char *username, const char *key)
{
    int result = 0;

    EnterCriticalSection(&connection_lock);

    /* Duplicate username check */
    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket != INVALID_SOCKET &&
            clients[i].registered &&
            _stricmp(clients[i].username, username) == 0)
        {
            LeaveCriticalSection(&connection_lock);
            return 0;
        }
    }

    /* Locate this socket */
    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket == socket)
        {
            strncpy_s(
                clients[i].username,
                sizeof(clients[i].username),
                username,
                _TRUNCATE
            );

            strncpy_s(
                clients[i].key,
                sizeof(clients[i].key),
                key,
                _TRUNCATE
            );

            clients[i].registered = 1;

            result = 1;
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);

    return result;
}

ServerClient *find_client_by_socket(SOCKET socket)
{
    ServerClient *result = NULL;

    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket == socket)
        {
            result = &clients[i];
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);

    return result;
}

int get_client_info_by_socket(
    SOCKET socket,
    char *username,
    size_t username_size,
    char *key,
    size_t key_size)
{
    int result = 0;

    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket == socket &&
            clients[i].registered)
        {
            strncpy_s(
                username,
                username_size,
                clients[i].username,
                _TRUNCATE
            );

            strncpy_s(
                key,
                key_size,
                clients[i].key,
                _TRUNCATE
            );

            result = 1;
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);

    return result;
}

int get_client_info_by_username(
    const char *username,
    SOCKET *socket,
    char *key,
    size_t key_size)
{
    int result = 0;

    EnterCriticalSection(&connection_lock);

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket != INVALID_SOCKET &&
            clients[i].registered &&
            _stricmp(clients[i].username, username) == 0)
        {
            *socket = clients[i].socket;

            strncpy_s(
                key,
                key_size,
                clients[i].key,
                _TRUNCATE
            );

            result = 1;
            break;
        }
    }

    LeaveCriticalSection(&connection_lock);

    return result;
}

void get_online_users(char *buffer, size_t buffer_size)
{
    buffer[0] = '\0';

    EnterCriticalSection(&connection_lock);

    int first = 1;

    for (int i = 0; i < MAX_CONNECTED_CLIENTS; i++)
    {
        if (clients[i].socket != INVALID_SOCKET &&
            clients[i].registered)
        {
            size_t current_len = strlen(buffer);

            if (!first)
            {
                strncat_s(
                    buffer,
                    buffer_size,
                    ", ",
                    _TRUNCATE
                );
            }

            strncat_s(
                buffer,
                buffer_size,
                clients[i].username,
                _TRUNCATE
            );

            if (strlen(buffer) == current_len)
                break;

            first = 0;
        }
    }

    LeaveCriticalSection(&connection_lock);
}