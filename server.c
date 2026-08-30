#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "config/constants.h"
#include "crypto/cipher.h"
#include "parser/server_parser.h"
#include "user/user_manager.h"
#include "utils/file_utils.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_CLIENTS FD_SETSIZE

typedef struct {
    SOCKET socket;
    struct sockaddr_in addr;
    int registered;
    char username[9];
    char key[7];
    char recv_buf[BUFFER_SIZE * 2];
    int recv_len;
} ClientState;

ClientState clients[MAX_CLIENTS];

void init_clients() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = INVALID_SOCKET;
        clients[i].registered = 0;
        clients[i].recv_len = 0;
    }
}

void remove_client(int index) {
    if (clients[index].socket != INVALID_SOCKET) {
        closesocket(clients[index].socket);
        
        if (clients[index].registered) {
            ListNode *current = head;
            ListNode *prev = NULL;
            while (current != NULL) {
                if (current->user != NULL && strcmp(current->user->username, clients[index].username) == 0) {
                    if (prev == NULL) {
                        head = current->next;
                    } else {
                        prev->next = current->next;
                    }
                    if (current == tail) {
                        tail = prev;
                        if (head == NULL) {
                            tail = NULL;
                        }
                    }
                    free(current->user);
                    free(current);
                    break;
                }
                prev = current;
                current = current->next;
            }
        }
        
        clients[index].socket = INVALID_SOCKET;
        clients[index].registered = 0;
        clients[index].recv_len = 0;
    }
}

int send_encrypted(SOCKET sock, const char* key, const char* msg, int len) {
    char* buf = (char*)malloc(len);
    if (!buf) return -1;
    memcpy(buf, msg, len);
    
    repeatedXOR((unsigned char*)buf, len, (unsigned char*)key);
    
    int sent = send(sock, buf, len, 0);
    free(buf);
    return sent;
}

void handle_client_data(int index) {
    ClientState *c = &clients[index];
    
    int bytes = recv(c->socket, c->recv_buf + c->recv_len, sizeof(c->recv_buf) - c->recv_len - 1, 0);
    if (bytes <= 0) {
        remove_client(index);
        return;
    }
    
    c->recv_len += bytes;
    c->recv_buf[c->recv_len] = '\0';
    
    if (!c->registered) {
        char *newline = strchr(c->recv_buf, '\n');
        if (!newline) {
            if (c->recv_len > 1024) remove_client(index);
            return;
        }
        
        int cmd_len = newline - c->recv_buf;
        int next_cmd_offset = cmd_len + 1;
        
        *newline = '\0';
        if (cmd_len > 0 && *(newline - 1) == '\r') {
            *(newline - 1) = '\0';
            cmd_len--;
        }
        
        RegisterData rd = register_parser(c->recv_buf);
        
        // Try KPA if registration was encrypted
        if (!rd.valid && cmd_len >= 6) {
            char extracted_key[7];
            const char *prefix = "REGIST";
            for (int k = 0; k < 6; k++) {
                extracted_key[k] = c->recv_buf[k] ^ prefix[k];
            }
            extracted_key[6] = '\0';
            
            char *dec_buf = _strdup(c->recv_buf);
            repeatedXOR((unsigned char*)dec_buf, cmd_len, (unsigned char*)extracted_key);
            rd = register_parser(dec_buf);
            free(dec_buf);
        }
        
        if (rd.valid) {
            if (registerUser(rd.username, rd.key, c->addr)) {
                c->registered = 1;
                strcpy(c->username, rd.username);
                strcpy(c->key, rd.key);
                
                char response[64];
                sprintf(response, "REGISTERED %s\n", rd.username);
                send_encrypted(c->socket, c->key, response, strlen(response));
            } else {
                char err[64];
                sprintf(err, "ERROR username %s already taken\n", rd.username);
                send(c->socket, err, strlen(err), 0);
                remove_client(index);
                return;
            }
        } else {
            char err[] = "ERROR invalid command format\n";
            send(c->socket, err, strlen(err), 0);
            remove_client(index);
            return;
        }
        
        if (c->recv_len > next_cmd_offset) {
            memmove(c->recv_buf, c->recv_buf + next_cmd_offset, c->recv_len - next_cmd_offset);
        }
        c->recv_len -= next_cmd_offset;
        return;
    }
    
    char *temp_buf = (char*)malloc(c->recv_len + 1);
    if (!temp_buf) return;
    
    memcpy(temp_buf, c->recv_buf, c->recv_len);
    temp_buf[c->recv_len] = '\0';
    
    repeatedXOR((unsigned char*)temp_buf, c->recv_len, (unsigned char*)c->key);
    
    int consumed = 0;
    
    while (consumed < c->recv_len) {
        char *cmd_start = temp_buf + consumed;
        char *newline = (char*)memchr(cmd_start, '\n', c->recv_len - consumed);
        
        if (!newline) {
            break; 
        }
        
        int cmd_len = newline - cmd_start;
        int next_cmd_offset = consumed + cmd_len + 1;
        
        *newline = '\0';
        int had_cr = 0;
        if (cmd_len > 0 && *(newline - 1) == '\r') {
            *(newline - 1) = '\0';
            had_cr = 1;
        }
        
        if (strncmp(cmd_start, "SEND TO ", 8) == 0) {
            MessageData md = message_parser(cmd_start);
            if (md.valid) {
                User *target = searchUser(md.target_user);
                if (target) {
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (clients[j].registered && strcmp(clients[j].username, md.target_user) == 0) {
                            char fwd[BUFFER_SIZE + 64];
                            sprintf(fwd, "FROM %s: %s\n", c->username, md.message);
                            send_encrypted(clients[j].socket, clients[j].key, fwd, strlen(fwd));
                            break;
                        }
                    }
                } else {
                    char err[64];
                    sprintf(err, "ERROR %s is not online\n", md.target_user);
                    send_encrypted(c->socket, c->key, err, strlen(err));
                }
            } else {
                char err[] = "ERROR invalid command format\n";
                send_encrypted(c->socket, c->key, err, strlen(err));
            }
            consumed = next_cmd_offset;
        }
        else if (strncmp(cmd_start, "SENDFILE TO ", 12) == 0) {
            char target[32], filename[256];
            int size = 0;
            if (sscanf(cmd_start + 12, "%31s %255s %d", target, filename, &size) == 3) {
                if (size > MAX_FILE_SIZE) {
                    char err[] = "ERROR file too large\n";
                    send_encrypted(c->socket, c->key, err, strlen(err));
                    consumed = next_cmd_offset;
                    continue;
                }
                
                int bytes_after_newline = c->recv_len - next_cmd_offset;
                if (bytes_after_newline < size) {
                    *newline = '\n';
                    if (had_cr) *(newline - 1) = '\r';
                    break;
                }
                
                User *tgt = searchUser(target);
                if (tgt) {
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (clients[j].registered && strcmp(clients[j].username, target) == 0) {
                            char header[512];
                            int header_len = sprintf(header, "RECVFILE FROM %s: %s (%d bytes)\n", c->username, filename, size);
                            
                            char *fwd_buf = (char*)malloc(header_len + size);
                            if (fwd_buf) {
                                memcpy(fwd_buf, header, header_len);
                                memcpy(fwd_buf + header_len, temp_buf + next_cmd_offset, size);
                                send_encrypted(clients[j].socket, clients[j].key, fwd_buf, header_len + size);
                                free(fwd_buf);
                            }
                            break;
                        }
                    }
                } else {
                    char err[64];
                    sprintf(err, "ERROR %s is not online\n", target);
                    send_encrypted(c->socket, c->key, err, strlen(err));
                }
                
                consumed = next_cmd_offset + size;
            } else {
                char err[] = "ERROR invalid command format\n";
                send_encrypted(c->socket, c->key, err, strlen(err));
                consumed = next_cmd_offset;
            }
        }
        else if (strcmp(cmd_start, "QUIT") == 0) {
            char res[64];
            sprintf(res, "GOODBYE %s\n", c->username);
            send_encrypted(c->socket, c->key, res, strlen(res));
            free(temp_buf);
            remove_client(index);
            return;
        }
        else if (strcmp(cmd_start, "LIST") == 0) {
            char res[1024];
            strcpy(res, "ONLINE ");
            int first = 1;
            for (int j = 0; j < MAX_CLIENTS; j++) {
                if (clients[j].registered) {
                    if (!first) strcat(res, ", ");
                    strcat(res, clients[j].username);
                    first = 0;
                }
            }
            strcat(res, "\n");
            send_encrypted(c->socket, c->key, res, strlen(res));
            consumed = next_cmd_offset;
        }
        else {
            char err[] = "ERROR unknown command\n";
            send_encrypted(c->socket, c->key, err, strlen(err));
            consumed = next_cmd_offset;
        }
    }
    
    free(temp_buf);
    
    if (consumed > 0) {
        if (c->recv_len > consumed) {
            memmove(c->recv_buf, c->recv_buf + consumed, c->recv_len - consumed);
        }
        c->recv_len -= consumed;
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    
    init_clients();
    
    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return 1;
    }
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed.\n");
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    
    if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed.\n");
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    fd_set readfds;
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        SOCKET max_sd = server_sock;
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            SOCKET s = clients[i].socket;
            if (s != INVALID_SOCKET) {
                FD_SET(s, &readfds);
            }
        }
        
        int activity = select(0, &readfds, NULL, NULL, NULL);
        if (activity == SOCKET_ERROR) {
            printf("Select error.\n");
            break;
        }
        
        if (FD_ISSET(server_sock, &readfds)) {
            struct sockaddr_in client_addr;
            int addrlen = sizeof(client_addr);
            SOCKET new_socket = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);
            
            if (new_socket != INVALID_SOCKET) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].socket == INVALID_SOCKET) {
                        clients[i].socket = new_socket;
                        clients[i].addr = client_addr;
                        clients[i].registered = 0;
                        clients[i].recv_len = 0;
                        break;
                    }
                }
            }
        }
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != INVALID_SOCKET && FD_ISSET(clients[i].socket, &readfds)) {
                handle_client_data(i);
            }
        }
    }
    
    closesocket(server_sock);
    WSACleanup();
    return 0;
}
