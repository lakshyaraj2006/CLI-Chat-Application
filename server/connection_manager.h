#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <winsock2.h>
#include <windows.h>

#define MAX_CONNECTED_CLIENTS 100

typedef struct
{
    SOCKET socket;
    struct sockaddr_in address;

    char username[9];
    char key[7];

    int registered;
} ServerClient;

void connection_manager_init(void);
void connection_manager_cleanup(void);

int add_client(SOCKET socket, struct sockaddr_in address);
void remove_client(SOCKET socket);

int register_client(SOCKET socket, const char *username, const char *key);

ServerClient *find_client_by_socket(SOCKET socket);

int get_client_info_by_socket(
    SOCKET socket,
    char *username,
    size_t username_size,
    char *key,
    size_t key_size
);

int get_client_info_by_username(
    const char *username,
    SOCKET *socket,
    char *key,
    size_t key_size
);

int is_username_taken(const char *username);

void get_online_users(char *buffer, size_t buffer_size);

CRITICAL_SECTION *get_connection_lock(void);

#endif