#ifndef SERVER_PARSER_H
#define SERVER_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../config/constants.h"

typedef struct
{
    char username[9];
    char key[7];
    int valid;
} RegisterData;

typedef struct
{
    char target_user[9];
    char message[MAX_MSG_SIZE];
    int valid;
} MessageData;

static inline void trim_spaces(char *str)
{
    int start = 0;
    int end = (int)strlen(str) - 1;

    while (str[start] == ' ')
    {
        start++;
    }

    while (end >= start && str[end] == ' ')
    {
        end--;
    }

    int i = 0;

    while (start <= end)
    {
        str[i++] = str[start++];
    }

    str[i] = '\0';
}

static inline RegisterData register_parser(char *str)
{
    RegisterData result;

    result.valid = 0;
    result.username[0] = '\0';
    result.key[0] = '\0';

    char *tokens[10];
    int cnt = 0;

    char *token = strtok(str, " ");

    while (token != NULL)
    {
        if (cnt >= 10)
        {
            break;
        }

        tokens[cnt++] = token;
        token = strtok(NULL, " ");
    }

    if (cnt != 4 ||
        strcmp(tokens[0], "REGISTER") != 0 ||
        strcmp(tokens[2], "KEY") != 0)
    {
        printf("Invalid command format.\n");
        return result;
    }

    if (strlen(tokens[1]) > 8 ||
        strlen(tokens[3]) != KEY_LENGTH)
    {
        printf("Invalid username or key.\n");
        return result;
    }

    strcpy(result.username, tokens[1]);
    strcpy(result.key, tokens[3]);

    result.valid = 1;

    return result;
}

static inline MessageData message_parser(const char *str)
{
    MessageData result;

    result.valid = 0;
    result.target_user[0] = '\0';
    result.message[0] = '\0';

    if (strncmp(str, "SEND TO ", 8) != 0)
    {
        return result;
    }

    const char *p = str + 8;
    while (*p == ' ') p++;
    if (*p == '\0') return result;

    char *colon = strchr(p, ':');
    if (colon != NULL)
    {
        size_t target_len = colon - p;
        if (target_len == 0 || target_len > 8) return result;
        strncpy(result.target_user, p, target_len);
        result.target_user[target_len] = '\0';
        while (target_len > 0 && result.target_user[target_len - 1] == ' ')
        {
            result.target_user[--target_len] = '\0';
        }

        const char *msg = colon + 1;
        while (*msg == ' ') msg++;
        if (strlen(msg) >= MAX_MSG_SIZE) return result;
        strcpy(result.message, msg);
        result.valid = (target_len > 0 && strlen(result.message) > 0);
        return result;
    }
    else
    {
        char *space = strchr(p, ' ');
        if (space == NULL) return result;

        size_t target_len = space - p;
        if (target_len == 0 || target_len > 8) return result;
        strncpy(result.target_user, p, target_len);
        result.target_user[target_len] = '\0';

        const char *msg = space + 1;
        while (*msg == ' ') msg++;
        if (strlen(msg) >= MAX_MSG_SIZE) return result;
        strcpy(result.message, msg);
        result.valid = (target_len > 0 && strlen(result.message) > 0);
        return result;
    }
}

#endif /* SERVER_PARSER_H */