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
    char message[BUFFER_SIZE];
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

static inline MessageData message_parser(char *str)
{
    MessageData result;

    result.valid = 0;
    result.target_user[0] = '\0';
    result.message[0] = '\0';

    char *tokens[10];
    int cnt = 0;

    /*
     * Split only at the first ':'.
     * This allows ':' to remain inside the message.
     */
    char *separator = strchr(str, ':');

    if (separator == NULL)
    {
        printf("Invalid command format.\n");
        return result;
    }

    *separator = '\0';

    char *command_part = str;
    char *message_part = separator + 1;

    trim_spaces(command_part);
    trim_spaces(message_part);

    char *subtokens[10];
    int cnt1 = 0;

    char *subtoken = strtok(command_part, " ");

    while (subtoken != NULL)
    {
        if (cnt1 >= 10)
        {
            break;
        }

        subtokens[cnt1++] = subtoken;
        subtoken = strtok(NULL, " ");
    }

    if (cnt1 != 3 ||
        strcmp(subtokens[0], "SEND") != 0 ||
        strcmp(subtokens[1], "TO") != 0)
    {
        printf("Invalid command format.\n");
        return result;
    }

    if (strlen(subtokens[2]) > 8)
    {
        printf("Invalid username.\n");
        return result;
    }

    if (strlen(message_part) >= BUFFER_SIZE)
    {
        printf("Message too large.\n");
        return result;
    }

    strcpy(result.target_user, subtokens[2]);
    strcpy(result.message, message_part);

    result.valid = 1;

    return result;
}

#endif /* SERVER_PARSER_H */