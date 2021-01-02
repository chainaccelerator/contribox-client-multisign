# include "emscripten.h"
# include "contribox.h"
# include <stdio.h>
# include <time.h>
# include <stdlib.h>

/* char *generateAesKey(const char *user_password) {
    char *base58_key;
    unsigned char *key;

    // maybe there's not a real use case for scrypt here
    // wally_scrypt(user_password, strlen(user_password), NULL, (size_t)0, 16384, 8, 1, key, 32);
    wally_sha256d(user_password, )
} */

/* EMSCRIPTEN_KEEPALIVE
char *encryptConfig(const unsigned char *password, char *clearConfig) {
    char *encryptedConfig
    // generate the AES key
    wally_scrypt(password, strlen(password))
    return encryptedConfig;
} */

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
char *hdKeyFromSeed(const char *seed_hex) {
    char *xprv;
    struct ext_key *hdKey;
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t written;
    int ret;

    wally_hex_to_bytes(seed_hex, seed, sizeof(seed), &written);

    hdKey = malloc(sizeof(*hdKey));

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

    hdKey = malloc(sizeof(*hdKey));

    bip32_key_from_base58(xprv, hdKey);

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
    unsigned char aesKey[PBKDF2_HMAC_SHA256_LEN];
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
                            aesKey, 
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
    cipher = calloc(cipher_len, sizeof(*cipher));

    // encrypt message
    if ((ret = wally_aes_cbc(
                aesKey, 
                PBKDF2_HMAC_SHA256_LEN, 
                initVector,
                AES_BLOCK_LEN,
                (unsigned char*)toEncrypt,
                strlen(toEncrypt),
                AES_FLAG_ENCRYPT,
                cipher,
                cipher_len,
                &written
                )) != 0) {
        printf("wally_aes_cbc failed with %d\n", ret);
        free(cipher);
        return "";
    };
    wally_base58_from_bytes(cipher, cipher_len, BASE58_FLAG_CHECKSUM, &encryptedFile);

    free(cipher);

    return encryptedFile;
}
// EMSCRIPTEN_KEEPALIVE
// char *generateMasterBlindingKey(const unsigned char *seed) {
//     unsigned char bytes_out[HMAC_SHA512_LEN];
//     char *masterBlindingKey;
//     int ret;

//     if ((ret = wally_asset_blinding_key_from_seed(seed, sizeof(seed), bytes_out, sizeof(bytes_out))) != 0) {
//         printf("wally_asset_blinding_key_from_seed failed with %d error code\n", ret);
//         return "";
//     }

//     wally_hex_from_bytes(bytes_out, sizeof(bytes_out), &masterBlindingKey);

//     return masterBlindingKey;
// }
