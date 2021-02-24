#include "contribox.h"

unsigned char   *encryptWithAes(const char *toEncrypt, const unsigned char *key, size_t *cipher_len) {
    unsigned char   *cipher = NULL;
    unsigned char   initVector[AES_BLOCK_LEN];
    size_t          written;
    int             ret = 1;

    if (*cipher_len)
        *cipher_len = 0;

    // get initialization vector of 16 bytes
    getRandomBytes(initVector, AES_BLOCK_LEN);

    // get the length of the cipher
    *cipher_len = strlen(toEncrypt) / 16 * 16 + 16;
    if (!(cipher = calloc(*cipher_len + AES_BLOCK_LEN, sizeof(*cipher)))) {
        printf(MEMORY_ERROR);
        return cipher;
    };

    // copy the initialization vector at the head of our cipher
    memcpy(cipher, initVector, AES_BLOCK_LEN);

    // encrypt message
    if ((ret = wally_aes_cbc(
                key, 
                PBKDF2_HMAC_SHA256_LEN, 
                initVector,
                AES_BLOCK_LEN,
                (unsigned char*)toEncrypt,
                strlen(toEncrypt),
                AES_FLAG_ENCRYPT,
                cipher + AES_BLOCK_LEN,
                *cipher_len,
                &written
                )) != 0) {
        printf("wally_aes_cbc failed with %d\n", ret);
    };

    *cipher_len += AES_BLOCK_LEN; 

    return cipher;
}
