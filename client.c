#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

#include "config/constants.h"
#include "crypto/cipher.h"
#include "parser/client_parser.h"
#include "utils/file_utils.h"

#pragma comment(lib, "ws2_32.lib")

SOCKET client_socket;
char current_key[KEY_LENGTH + 1] = {0};
int is_registered = 0;
int running = 1;

// Global buffer for receiving
char recv_buf[BUFFER_SIZE * 2];
int recv_len = 0;

void print_prompt() {
    printf("client$ ");
    fflush(stdout);
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

unsigned __stdcall receive_thread(void* arg) {
    while (running) {
        int bytes = recv(client_socket, recv_buf + recv_len, sizeof(recv_buf) - recv_len - 1, 0);
        if (bytes <= 0) {
            printf("\nServer disconnected.\n");
            running = 0;
            exit(1);
        }
        
        recv_len += bytes;
        recv_buf[recv_len] = '\0';
        
        if (!is_registered) {
            // Before registration, server responses (like ERROR) might not be encrypted?
            // Actually, in server.c, if register fails, it sends ERROR unencrypted:
            // send(c->socket, err, strlen(err), 0);
            // If succeeds, it sends REGISTERED encrypted:
            // send_encrypted(c->socket, c->key, response, strlen(response));
            
            // So we must try to check if it's plaintext ERROR or encrypted REGISTERED.
            // Let's decrypt to a temp buf
            char* temp_buf = (char*)malloc(recv_len + 1);
            memcpy(temp_buf, recv_buf, recv_len);
            temp_buf[recv_len] = '\0';
            
            repeatedXOR((unsigned char*)temp_buf, recv_len, (unsigned char*)current_key);
            
            char* newline = strchr(temp_buf, '\n');
            char* plain_newline = strchr(recv_buf, '\n');
            
            int consumed = 0;
            
            if (plain_newline && strncmp(recv_buf, "ERROR", 5) == 0) {
                *plain_newline = '\0';
                printf("\nserver$ %s\n", recv_buf);
                consumed = (plain_newline - recv_buf) + 1;
                print_prompt();
            } else if (newline && strncmp(temp_buf, "REGISTERED", 10) == 0) {
                *newline = '\0';
                printf("\nserver$ %s\n", temp_buf);
                is_registered = 1;
                consumed = (newline - temp_buf) + 1;
                print_prompt();
            } else if (plain_newline || newline) {
                // Unknown, just consume one line to avoid infinite loop
                consumed = plain_newline ? (plain_newline - recv_buf) + 1 : (newline - temp_buf) + 1;
            }
            
            free(temp_buf);
            
            if (consumed > 0) {
                if (recv_len > consumed) {
                    memmove(recv_buf, recv_buf + consumed, recv_len - consumed);
                }
                recv_len -= consumed;
            }
            continue;
        }
        
        // Registered state processing
        char* temp_buf = (char*)malloc(recv_len + 1);
        if (!temp_buf) continue;
        
        memcpy(temp_buf, recv_buf, recv_len);
        temp_buf[recv_len] = '\0';
        
        repeatedXOR((unsigned char*)temp_buf, recv_len, (unsigned char*)current_key);
        
        int consumed = 0;
        
        while (consumed < recv_len) {
            char* cmd_start = temp_buf + consumed;
            char* newline = (char*)memchr(cmd_start, '\n', recv_len - consumed);
            
            if (!newline) {
                break;
            }
            
            int cmd_len = newline - cmd_start;
            int next_cmd_offset = consumed + cmd_len + 1;
            
            *newline = '\0';
            if (cmd_len > 0 && *(newline - 1) == '\r') {
                *(newline - 1) = '\0';
                cmd_len--;
            }
            
            if (strncmp(cmd_start, "RECVFILE FROM ", 14) == 0) {
                char sender[32], filename[256];
                int size = 0;
                
                // Format: RECVFILE FROM <sender>: <filename> (<size> bytes)
                char* colon = strchr(cmd_start + 14, ':');
                if (colon) {
                    *colon = '\0';
                    strcpy(sender, cmd_start + 14);
                    
                    char* paren = strchr(colon + 1, '(');
                    if (paren) {
                        char* space = paren - 1;
                        while (space > colon + 1 && *space == ' ') space--;
                        *(space + 1) = '\0';
                        
                        char* fname = colon + 1;
                        while (*fname == ' ') fname++;
                        strcpy(filename, fname);
                        
                        sscanf(paren + 1, "%d", &size);
                        
                        if (recv_len - next_cmd_offset < size) {
                            // Not enough data yet
                            *newline = '\n';
                            break;
                        }
                        
                        printf("\n%s\n", cmd_start);
                        
                        char out_filename[512];
                        sprintf(out_filename, "received_%s", get_basename(filename));
                        
                        FILE* f = fopen(out_filename, "wb");
                        if (f) {
                            fwrite(temp_buf + next_cmd_offset, 1, size, f);
                            fclose(f);
                            printf("[content saved to ./%s]\n", out_filename);
                        } else {
                            printf("[error saving file to ./%s]\n", out_filename);
                        }
                        
                        consumed = next_cmd_offset + size;
                        print_prompt();
                        continue;
                    }
                }
            } else if (strncmp(cmd_start, "GOODBYE", 7) == 0) {
                printf("\nserver$ %s\n", cmd_start);
                running = 0;
                free(temp_buf);
                exit(0);
            } else {
                printf("\n%s\n", cmd_start);
                consumed = next_cmd_offset;
                print_prompt();
                continue;
            }
            
            consumed = next_cmd_offset;
        }
        
        free(temp_buf);
        
        if (consumed > 0) {
            if (recv_len > consumed) {
                memmove(recv_buf, recv_buf + consumed, recv_len - consumed);
            }
            recv_len -= consumed;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }
    
    char* server_ip = argv[1];
    int port = atoi(argv[2]);
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        printf("Socket creation failed.\n");
        WSACleanup();
        return 1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection to server failed.\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    _beginthreadex(NULL, 0, receive_thread, NULL, 0, NULL);
    
    char input[BUFFER_SIZE];
    
    while (running) {
        print_prompt();
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove trailing newline
        input[strcspn(input, "\r\n")] = '\0';
        if (strlen(input) == 0) continue;
        
        if (!is_registered) {
            if (strncmp(input, "REGISTER ", 9) == 0) {
                // Extract key
                char* key_ptr = strstr(input, " KEY ");
                if (key_ptr) {
                    strncpy(current_key, key_ptr + 5, KEY_LENGTH);
                    current_key[KEY_LENGTH] = '\0';
                    
                    char out_buf[1024];
                    sprintf(out_buf, "%s\n", input);
                    
                    // Client encrypts the registration string with the key
                    send_encrypted(client_socket, current_key, out_buf, strlen(out_buf));
                } else {
                    printf("Invalid register format. Expected: REGISTER <username> KEY <6-char-key>\n");
                }
            } else {
                printf("Please register first: REGISTER <username> KEY <6-char-key>\n");
            }
        } else {
            char target[32], filepath[256];
            if (parse_sendfile_command(input, target, sizeof(target), filepath, sizeof(filepath))) {
                if (!is_txt_file(filepath)) {
                    printf("ERROR only .txt files are supported\n");
                    continue;
                }
                
                FILE* f = fopen(filepath, "rb");
                if (!f) {
                    printf("ERROR file not found: %s\n", filepath);
                    continue;
                }
                
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);
                
                if (fsize > MAX_FILE_SIZE) {
                    printf("ERROR file too large. Max size is %d bytes.\n", MAX_FILE_SIZE);
                    fclose(f);
                    continue;
                }
                
                char header[512];
                int header_len = sprintf(header, "SENDFILE TO %s %s %ld\n", target, filepath, fsize);
                
                char* send_buf = (char*)malloc(header_len + fsize);
                if (!send_buf) {
                    printf("Memory allocation failed.\n");
                    fclose(f);
                    continue;
                }
                
                memcpy(send_buf, header, header_len);
                fread(send_buf + header_len, 1, fsize, f);
                fclose(f);
                
                send_encrypted(client_socket, current_key, send_buf, header_len + fsize);
                free(send_buf);
            } else {
                char out_buf[BUFFER_SIZE];
                sprintf(out_buf, "%s\n", input);
                send_encrypted(client_socket, current_key, out_buf, strlen(out_buf));
                
                if (strcmp(input, "QUIT") == 0) {
                    // Wait for GOODBYE from server, receive_thread will exit the process
                }
            }
        }
    }
    
    closesocket(client_socket);
    WSACleanup();
    return 0;
}
