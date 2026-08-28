#ifndef USER_MANAGER_H
#define USER_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

typedef struct {
    char username[9];
    char key[7];
    struct sockaddr_in client_addr;
} User;

typedef struct ListNode {
    User *user;
    struct ListNode *next;
} ListNode;

static ListNode *head = NULL;
static ListNode *tail = NULL;

static inline User* searchUser(char username[]) {
    ListNode *current = head;

    while (current != NULL) {
        if (_stricmp(current->user->username, username) == 0) {
            return current->user;
        }

        current = current->next;
    }

    return NULL;
}

static inline int registerUser(char username[], char key[], struct sockaddr_in client_addr) {
    if (searchUser(username)) {
        printf("ERROR: Username '%s' is already taken.\n", username);
        return 0;
    }

    User *newUser = (User *)malloc(sizeof(User));

    if (newUser == NULL) {
        printf("Memory allocation failed.\n");
        return 0;
    }

    strcpy(newUser->username, username);
    strcpy(newUser->key, key);
    newUser->client_addr = client_addr;

    ListNode *newNode = (ListNode *)malloc(sizeof(ListNode));

    if (newNode == NULL) {
        printf("Memory allocation failed.\n");
        free(newUser);
        return 0;
    }

    newNode->user = newUser;
    newNode->next = NULL;

    if (head == NULL) {
        head = newNode;
        tail = newNode;
    } else {
        tail->next = newNode;
        tail = newNode;
    }

    return 1;
}

static inline char* getUsername(struct sockaddr_in client_addr) {
    ListNode *current = head;

    while (current != NULL) {
        if (current->user->client_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
            current->user->client_addr.sin_port == client_addr.sin_port) {
            return current->user->username;
        }

        current = current->next;
    }

    return NULL;
}

#endif // USER_MANAGER_H
