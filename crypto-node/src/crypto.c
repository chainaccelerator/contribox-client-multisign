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

char   *decryptWithAes(const char *toDecrypt, const unsigned char *key) {
    unsigned char   initVector[AES_BLOCK_LEN];

    unsigned char   *clear = NULL;
    size_t          clear_len;
    unsigned char   *cipher = NULL;
    size_t          cipher_len;

    size_t          written;
    int             ret = 1;

    // get the bytes length of the cipher 
    if ((ret = wally_base58_get_length(toDecrypt, &written)) != 0) {
        printf("wally_base58_get_length failed with %d\n", ret);
        goto cleanup;
    };

    if (written == strlen(toDecrypt)) {
        printf("can't get the length of the decoded base58 string\n");
        goto cleanup;
    };

    // malloc the cipher in bytes
    cipher_len = written;
    if (!(cipher = calloc(cipher_len, sizeof(*cipher)))) {
        printf(MEMORY_ERROR);
        goto cleanup;
    };

    // base58 to bytes
    if ((ret = wally_base58_to_bytes(toDecrypt, BASE58_FLAG_CHECKSUM, cipher, cipher_len, &written)) != 0) {
        printf("wally_base58_to_bytes failed with %d\n", ret);
        goto cleanup;
    };

    cipher_len -= BASE58_CHECKSUM_LEN;

    // retrieve the iv from the first 16B
    memcpy(initVector, cipher, AES_BLOCK_LEN);
    cipher += AES_BLOCK_LEN;
    cipher_len -= AES_BLOCK_LEN;

    // get the clear message len
    clear_len = (cipher_len) / 16 * 16;
    if (!(clear = calloc(clear_len + 1, sizeof(*clear)))) {
        printf(MEMORY_ERROR);
        goto cleanup;
    };

    // decrypt the cipher
    if ((ret = wally_aes_cbc(
                key,
                PBKDF2_HMAC_SHA256_LEN,
                initVector,
                AES_BLOCK_LEN,
                cipher,
                cipher_len,
                AES_FLAG_DECRYPT,
                clear,
                clear_len,
                &written
                )) != 0) {
        printf("wally_aes_cbc failed with %d\n", ret);
        clearThenFree(clear, clear_len);
        goto cleanup;
    };

cleanup:
    clearThenFree(cipher - AES_BLOCK_LEN, cipher_len + AES_BLOCK_LEN);

    return (char *)clear;
}
