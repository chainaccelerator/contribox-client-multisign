# include "emscripten.h"
# include "contribox.h"
# include <stdio.h>
# include <time.h>
# include <stdlib.h>

// FIXME: set all the memory that contains private material to zero when it's not used anymore

unsigned char *convertHexToBytes(const char *hexstring, size_t *bytes_len) {
    /* takes a hexstring, allocates and returns a bytes array */
    unsigned char *bytes;
    int ret;
    size_t written;

    *bytes_len = strlen(hexstring) / 2;
    if (!(bytes = malloc(*bytes_len))) {
        printf("Memory allocation error\n");
        return NULL;
    }

    if ((ret = wally_hex_to_bytes(hexstring, bytes, *bytes_len, &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        return NULL;
    }

    return bytes;
}

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
    int ret;
    char *mnemonic;

    if ((ret = bip39_mnemonic_from_bytes(NULL, entropy, entropy_len, &mnemonic)) != 0) {
        printf("mnemonic generation failed with %d error code\n", ret);
        return "";
    }
    
    return mnemonic;
}

EMSCRIPTEN_KEEPALIVE
char *generateSeed(const char *mnemonic, const char *passphrase) {
    int ret;
    size_t written;
    unsigned char seed[BIP39_SEED_LEN_512];
    char *_passphrase;
    size_t passphrase_len;
    char *seed_hex;

    passphrase_len = strlen(passphrase);

    if (passphrase_len == 0) {
        _passphrase = NULL;
    } 
    else {
        _passphrase = calloc(passphrase_len + 1, sizeof(*passphrase));
        memcpy(_passphrase, passphrase, passphrase_len);
    }

    if ((ret = bip39_mnemonic_to_seed(mnemonic, _passphrase, seed, BIP39_SEED_LEN_512, &written)) != 0) {
        printf("bip39_mnemonic_to_seed failed with %d error code\n", ret);
        return "";
    }

    wally_hex_from_bytes(seed, BIP39_SEED_LEN_512, &seed_hex);

    memset(seed, '\0', BIP39_SEED_LEN_512);

    if (_passphrase) {
        memset(_passphrase, '\0', passphrase_len);
        free(_passphrase);
    }

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
    if ((ret = wally_asset_blinding_key_from_seed(seed, BIP39_SEED_LEN_512, bytes_out, HMAC_SHA512_LEN)) != 0) {
        printf("wally_asset_blinding_key_from_seed failed with %d error code\n", ret);
        return "";
    }

    memset(seed, '\0', BIP39_SEED_LEN_512);

    wally_hex_from_bytes(bytes_out, HMAC_SHA512_LEN, &masterBlindingKey);

    return masterBlindingKey;
}

EMSCRIPTEN_KEEPALIVE
char *hdKeyFromSeed(const char *seed_hex) {
    struct ext_key *hdKey;
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t written;
    int ret;
    char *xprv;

    wally_hex_to_bytes(seed_hex, seed, BIP39_SEED_LEN_512, &written);

    if ((ret = bip32_key_from_seed_alloc(seed, BIP39_SEED_LEN_512, BIP32_VER_MAIN_PRIVATE, (uint32_t)0, &hdKey)) != 0) {
        printf("bip32_key_from_seed failed with %d error\n", ret);
        return "";
    } 

    memset(seed, '\0', BIP39_SEED_LEN_512);

    if ((ret = bip32_key_to_base58(hdKey, BIP32_FLAG_KEY_PRIVATE, &xprv)) != 0) {
        printf("bip32_key_to_base58");
        return "";
    };

    bip32_key_free(hdKey);

    return xprv;
}

EMSCRIPTEN_KEEPALIVE
char *xpubFromXprv(const char *xprv) {
    struct ext_key *hdKey;
    char *xpub;
    int ret;

    if (!(hdKey = malloc(sizeof(*hdKey)))) {
        printf("Memory allocation error\n");
        return "";
    }; 

    if ((ret = bip32_key_from_base58(xprv, hdKey)) != 0) {
        printf("bip32_key_from_base58 failed with %d error code\n", ret);
        return "";
    };

    if ((ret = bip32_key_to_base58(hdKey, BIP32_FLAG_KEY_PUBLIC, &xpub)) != 0) {
        printf("bip32_key_to_base58 failed with %d error code\n", ret);
        return "";
    };

    bip32_key_free(hdKey);

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
    memset(&key, '\0', sizeof(key));

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
char *decryptFileWithPassword(const char *encryptedFile, const char *userPassword) {
    unsigned char key[PBKDF2_HMAC_SHA256_LEN];
    unsigned char initVector[AES_BLOCK_LEN];

    unsigned char *clear;
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
    if (!(clear = calloc(clear_len + 1, sizeof(*clear)))) {
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
    memset(key, '\0', sizeof(key));

    free(cipher - AES_BLOCK_LEN);

    return (char *)clear;
}

EMSCRIPTEN_KEEPALIVE
char *getBlindingKeyFromScript(const char *scriptPubkey, const char *masterBlindingKey, char *privateBlindingKey) {
    unsigned char private[EC_PRIVATE_KEY_LEN];
    unsigned char *assetBlindingKey;
    unsigned char *script;
    size_t script_len;
    size_t key_len; // HMAC_SHA512_LEN
    int ret;
    size_t written;

    // convert script pubkey to bytes
    if (!(script = convertHexToBytes(scriptPubkey, &script_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // convert master blinding key to bytes
    if (!(assetBlindingKey = convertHexToBytes(masterBlindingKey, &key_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // compute the private blinding key
    if ((ret = wally_asset_blinding_key_to_ec_private_key(assetBlindingKey, HMAC_SHA512_LEN, script, script_len, private, EC_PRIVATE_KEY_LEN)) != 0) {
        printf("wally_asset_blinding_key_to_ec_private_key failed with %d error code\n", ret);
        return "";
    }

    // convert the private key to hex string
    if ((ret = wally_hex_from_bytes(private, EC_PRIVATE_KEY_LEN, &privateBlindingKey)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return "";
    }

    memset(private, '\0', EC_PRIVATE_KEY_LEN);

    free(script);
    free(assetBlindingKey);
    
    return privateBlindingKey;
}

EMSCRIPTEN_KEEPALIVE
char *getAddressFromScript(const char *scriptPubkey, char *address) {
    unsigned char *script;
    unsigned char program[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
    size_t script_len;
    size_t written;
    int ret;

    // convert script pubkey to bytes
    if (!(script = convertHexToBytes(scriptPubkey, &script_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // create the witness program from the script
    if ((ret = wally_witness_program_from_bytes(script, script_len, WALLY_SCRIPT_SHA256, program, WALLY_SCRIPTPUBKEY_P2WSH_LEN, &written)) != 0) {
        printf("wally_witness_program_from_bytes failed with %d error code\n", ret);
        return "";
    }

    // create the unconfidential address from program
    if ((ret = wally_addr_segwit_from_bytes(program, WALLY_SCRIPTPUBKEY_P2WSH_LEN, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 0, &address)) != 0) {
        printf("wally_addr_segwit_from_bytes failed with %d error code\n", ret);
        return "";
    }

    free(script);

    return address;
}

EMSCRIPTEN_KEEPALIVE
char *getConfidentialAddressFromAddress(const char *address, const char *privkeyHex, char *confidentialAddress) {
    unsigned char *blindingPrivkey;
    unsigned char blindingPubkey[EC_PUBLIC_KEY_LEN];
    int ret;
    size_t privkey_len;

    // convert private key to bytes
    if (!(blindingPrivkey = convertHexToBytes(privkeyHex, &privkey_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // compute the blinding pubkey from privkey
    if ((ret = wally_ec_public_key_from_private_key(blindingPrivkey, EC_PRIVATE_KEY_LEN, blindingPubkey, EC_PUBLIC_KEY_LEN)) != 0) {
        printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
        return "";
    }

    // create the confidential address from the unconfidential one
    if ((ret = wally_confidential_addr_from_addr_segwit(
            address, 
            UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST,
            CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST,
            blindingPubkey, 
            EC_PUBLIC_KEY_LEN, 
            &confidentialAddress)) != 0) {
        printf("wally_confidential_addr_to_addr failed with %d error code\n", ret);
        return "";
    }

    memset(blindingPrivkey, '\0', EC_PRIVATE_KEY_LEN);
    free(blindingPrivkey);

    return confidentialAddress;
}

struct ext_key *getChildFromXpub(const char *xpub, const uint32_t *hdPath, const size_t path_len) {
    struct ext_key *hdKey;
    struct ext_key *child;
    int ret;

    if ((ret = bip32_key_from_base58_alloc(xpub, &hdKey)) != 0) {
        printf("bip32_key_from_base58 failed with %d error code\n", ret);
        return NULL;
    };

    if ((ret = bip32_key_from_parent_path_alloc(hdKey, hdPath, path_len, BIP32_FLAG_KEY_PUBLIC, &child)) != 0) {
        printf("bip32_key_from_parent_path failed with %d error code\n", ret);
        return NULL;
    }

    bip32_key_free(hdKey);

    return child;
}

EMSCRIPTEN_KEEPALIVE
char *getPubkeyFromXpub(const char *xpub, const uint32_t *hdPath, const size_t path_len) {
    struct ext_key *child;
    char *pubkey_hex;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];

    if ((child = getChildFromXpub(xpub, hdPath, path_len)) == NULL) {
        printf("getChildFromXpub failed\n");
        return "";
    }

    memcpy(pubkey, child->pub_key, EC_PUBLIC_KEY_LEN);

    bip32_key_free(child);

    wally_hex_from_bytes(pubkey, HMAC_SHA512_LEN, &pubkey_hex);

    return pubkey_hex;
}

EMSCRIPTEN_KEEPALIVE
char *getAddressFromXpub(const char *xpub, const uint32_t *hdPath, const size_t path_len) {
    struct ext_key *child;
    char *address;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    int ret;

    if ((child = getChildFromXpub(xpub, hdPath, path_len)) == NULL) {
        printf("getChildFromXpub failed\n");
        return "";
    }

    if ((ret = wally_bip32_key_to_addr_segwit(child, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, (uint32_t)0, &address)) != 0) {
        printf("wally_bip32_key_to_addr_segwit failed with %d error code\n", ret);
        return "";
    }

    bip32_key_free(child);

    return address;
}
