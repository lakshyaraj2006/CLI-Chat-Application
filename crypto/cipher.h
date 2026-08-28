#ifndef CIPHER_H
#define CIPHER_H

#include <stdlib.h>
#include "../config/constants.h"

static inline void generateKey(unsigned char key[]) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";

    for (int i = 0; i < KEY_LENGTH; i++) {
        key[i] = charset[rand() % 36];
    }

    key[KEY_LENGTH] = '\0';
}

static inline void repeatedXOR(unsigned char text[], int textLength, unsigned char key[]) {
    for (int i = 0; i < textLength; i++) {
        text[i] = text[i] ^ key[i % KEY_LENGTH];
    }
}

#endif // CIPHER_H
