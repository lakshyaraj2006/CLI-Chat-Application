#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

#include <winsock2.h>

typedef struct
{
    SOCKET socket;
    struct sockaddr_in address;
} ClientThreadArgs;

unsigned __stdcall client_handler(void *arg);

#endif