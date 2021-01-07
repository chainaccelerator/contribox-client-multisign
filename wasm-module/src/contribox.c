# include "emscripten.h"
# include "contribox.h"
# include <stdio.h>
# include <time.h>
# include <stdlib.h>

// FIXME: set all the memory that contains private material to zero when it's not used anymore

EMSCRIPTEN_KEEPALIVE
int is_elements() {
    int ret;
    size_t written;

    ret = wally_is_elements_build(&written);
    if (ret != 0) {
        return 0;
    }

    return written;
}

EMSCRIPTEN_KEEPALIVE
char *generateMnemonic(const unsigned char *entropy, size_t entropy_len) {
    char *mnemonic;
    int ret;

    if ((ret = bip39_mnemonic_from_bytes(NULL, entropy, entropy_len, &mnemonic)) != 0) {
        printf("mnemonic generation failed with %d error code\n", ret);
        return "";
    }
    return mnemonic;
}

EMSCRIPTEN_KEEPALIVE
char *generateSeed(const char *mnemonic) {
    int ret;
    size_t written;
    unsigned char seed[BIP39_SEED_LEN_512];
    char *seed_hex;

    if ((ret = bip39_mnemonic_to_seed(mnemonic, NULL, seed, sizeof(seed), &written)) != 0) {
        printf("bip39_mnemonic_to_seed failed with %d error code\n", ret);
        return "";
    }

    if (written != BIP39_SEED_LEN_512) {
        printf("seed is not %d long, but %lu", BIP39_SEED_LEN_512, (unsigned long)written);
        return "";
    }

    wally_hex_from_bytes(seed, sizeof(seed), &seed_hex);
    return seed_hex;
}

EMSCRIPTEN_KEEPALIVE
char *generateMasterBlindingKey(const char *seed_hex) {
    unsigned char bytes_out[HMAC_SHA512_LEN];
    unsigned char seed[BIP39_SEED_LEN_512];
    char *masterBlindingKey;
    int ret;
    size_t written;

    if ((ret = wally_hex_to_bytes(seed_hex, seed, BIP39_SEED_LEN_512, &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        return "";
    }
    if ((ret = wally_asset_blinding_key_from_seed(seed, sizeof(seed), bytes_out, sizeof(bytes_out))) != 0) {
        printf("wally_asset_blinding_key_from_seed failed with %d error code\n", ret);
        return "";
    }

    wally_hex_from_bytes(bytes_out, sizeof(bytes_out), &masterBlindingKey);

    return masterBlindingKey;
}

EMSCRIPTEN_KEEPALIVE
char *hdKeyFromSeed(const char *seed_hex) {
    char *xprv;
    struct ext_key *hdKey;
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t written;
    int ret;

    wally_hex_to_bytes(seed_hex, seed, sizeof(seed), &written);

    if (!(hdKey = malloc(sizeof(*hdKey)))) {
        printf("Memory allocation error\n");
        return "";
    }; 

    if ((ret = bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, (uint32_t)0, hdKey)) != 0) {
        printf("bip32_key_from_seed failed with %d error\n", ret);
        return "";
    } 

    if ((ret = bip32_key_to_base58(hdKey, BIP32_FLAG_KEY_PRIVATE, &xprv)) != 0) {
        printf("bip32_key_to_base58");
        return "";
    };

    free(hdKey);

    return xprv;
}

EMSCRIPTEN_KEEPALIVE
char *xpubFromXprv(const char *xprv) {
    char *xpub;
    struct ext_key *hdKey;
    int ret;

    if (!(hdKey = malloc(sizeof(*hdKey)))) {
        printf("Memory allocation error\n");
        return "";
    }; 

    if ((ret = bip32_key_from_base58(xprv, hdKey)) != 0) {
        printf("bip32_key_from_base58");
        return "";
    };

    if ((ret = bip32_key_to_base58(hdKey, BIP32_FLAG_KEY_PUBLIC, &xpub)) != 0) {
        printf("bip32_key_to_base58 failed");
        return "";
    };

    free(hdKey);

    return xpub;
}

EMSCRIPTEN_KEEPALIVE
char *encryptFileWithPassword(const char *userPassword, const char *toEncrypt, char *encryptedFile) {
    unsigned char *cipher;
    unsigned char key[PBKDF2_HMAC_SHA256_LEN];
    int cipher_len;
    size_t written;
    unsigned char initVector[AES_BLOCK_LEN];
    int ret;

    // generate key from password
    if ((ret = wally_pbkdf2_hmac_sha256(
                            (unsigned char*)userPassword, 
                            strlen(userPassword), 
                            NULL, 
                            (size_t)0,
                            0,
                            16384,
                            key, 
                            PBKDF2_HMAC_SHA256_LEN)) != 0) {
        printf("wally_pbkdf2_hmac_sha256 failed with %d\n", ret);
        return "";
    };

    // get initialization vector of 16 bytes
    srand((unsigned int)time(NULL));
    for (int i = 0; i < AES_BLOCK_LEN; i++) {
        initVector[i] = rand();
    }

    // get the length of the cipher
    cipher_len = strlen(toEncrypt) / 16 * 16 + 16;
    if (!(cipher = calloc(cipher_len + AES_BLOCK_LEN, sizeof(*cipher)))) {
        printf("Memory allocation error\n");
        return "";
    };
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
                cipher_len,
                &written
                )) != 0) {
        printf("wally_aes_cbc failed with %d\n", ret);
        free(cipher);
        return "";
    };

    if ((ret = wally_base58_from_bytes(cipher, cipher_len + AES_BLOCK_LEN, BASE58_FLAG_CHECKSUM, &encryptedFile)) != 0) {
        printf("wally_base58_from_bytes failed\n");
        free(cipher);
        return "";
    };

    free(cipher);

    return encryptedFile;
}

EMSCRIPTEN_KEEPALIVE
size_t getClearLenFromCipher(const char *encryptedFile) {
    size_t written;
    int ret;

    // get the bytes length of the cipher 
    if ((ret = wally_base58_get_length(encryptedFile, &written)) != 0) {
        printf("wally_base58_get_length failed with %d\n", ret);
        return -1;
    };
    if (written == strlen(encryptedFile)) {
        printf("can't get the length of the decoded base58 string\n");
        return -1;
    }

    written -= BASE58_CHECKSUM_LEN; 
    written -= AES_BLOCK_LEN;
    written /= 16;
    written *= 16;

    return written;
}

EMSCRIPTEN_KEEPALIVE
char *decryptFileWithPassword(const char *encryptedFile, const char *userPassword, unsigned char *clear) {
    unsigned char key[PBKDF2_HMAC_SHA256_LEN];
    unsigned char initVector[AES_BLOCK_LEN];

    unsigned char *cipher;
    size_t cipher_len;
    size_t clear_len;

    size_t written;
    int ret;

    // get the key from the password
    if ((ret = wally_pbkdf2_hmac_sha256(
                            (unsigned char*)userPassword, 
                            strlen(userPassword), 
                            NULL, 
                            (size_t)0,
                            0,
                            16384,
                            key, 
                            PBKDF2_HMAC_SHA256_LEN)) != 0) {
        printf("wally_pbkdf2_hmac_sha256 failed with %d\n", ret);
        return 0;
    };


    // get the bytes length of the cipher 
    if ((ret = wally_base58_get_length(encryptedFile, &written)) != 0) {
        printf("wally_base58_get_length failed with %d\n", ret);
        return "";
    };
    if (written == strlen(encryptedFile)) {
        printf("can't get the length of the decoded base58 string\n");
        return "";
    }

    // malloc the cipher in bytes
    cipher_len = written;
    if (!(cipher = calloc(cipher_len, sizeof(*cipher)))) {
        printf("Memory allocation error\n");
        return "";
    };

    // base58 to bytes
    if ((ret = wally_base58_to_bytes(encryptedFile, BASE58_FLAG_CHECKSUM, cipher, cipher_len, &written)) != 0) {
        printf("wally_base58_to_bytes failed with %d\n", ret);
        return "";
    };

    cipher_len -= BASE58_CHECKSUM_LEN;

    // retrieve the iv from the first 16B
    memcpy(initVector, cipher, AES_BLOCK_LEN);
    cipher += AES_BLOCK_LEN;
    cipher_len -= AES_BLOCK_LEN;

    // get the clear message len
    clear_len = (cipher_len) / 16 * 16;
    if (!(clear = calloc(clear_len, sizeof(*clear)))) {
        printf("Memory allocation error\n");
        return "";
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
        free(clear);
        free(cipher - AES_BLOCK_LEN);
        return "";
    };

    free(cipher - AES_BLOCK_LEN);

    return (char *)clear;
}
