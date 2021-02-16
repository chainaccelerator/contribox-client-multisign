# include "contribox.h"

EMSCRIPTEN_KEEPALIVE
int initializePRNG(const unsigned char *entropy, const size_t len) {
    int ret = 1;
    if ((ret = wally_secp_randomize(entropy, len)) != 0) {
        return ret;
    }
    
    srand((unsigned int)*entropy);

    return ret;
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

    if ((ret = wally_hex_from_bytes(seed, BIP39_SEED_LEN_512, &seed_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return "";
    }

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

    if ((ret = wally_hex_from_bytes(bytes_out, HMAC_SHA512_LEN, &masterBlindingKey)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return "";
    }

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
        printf(MEMORY_ERROR);
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
char    *encryptFileWithPassword(const char *userPassword, const char *toEncrypt, char *encryptedFile) {
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
    getRandomBytes(initVector, AES_BLOCK_LEN);

    // get the length of the cipher
    cipher_len = strlen(toEncrypt) / 16 * 16 + 16;
    if (!(cipher = calloc(cipher_len + AES_BLOCK_LEN, sizeof(*cipher)))) {
        printf(MEMORY_ERROR);
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
        printf(MEMORY_ERROR);
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
        printf(MEMORY_ERROR);
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
char *getBlindingKeyFromScript(const char *script_hex, const char *masterBlindingKey) {
    unsigned char private[EC_PRIVATE_KEY_LEN];
    unsigned char *assetBlindingKey;
    unsigned char *script;
    unsigned char *program;
    char *privateBlindingKey = NULL;
    size_t script_len;
    size_t key_len; // HMAC_SHA512_LEN
    int ret;
    size_t written;
    int isP2WSH;

    // convert script pubkey to bytes
    if (!(script = convertHexToBytes(script_hex, &script_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // convert master blinding key to bytes
    if (!(assetBlindingKey = convertHexToBytes(masterBlindingKey, &key_len))) {
        printf("convertHexToBytes failed\n");
        return "";
    }

    // get the program from the script
    if (!(program = getWitnessProgram(script, script_len, &isP2WSH))) {
        printf("getWitnessProgram failed\n");
        return "";
    }

    // compute the private blinding key
    if ((ret = wally_asset_blinding_key_to_ec_private_key(assetBlindingKey, HMAC_SHA512_LEN, 
                                                        program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN, 
                                                        private, EC_PRIVATE_KEY_LEN)) != 0) {
        printf("wally_asset_blinding_key_to_ec_private_key failed with %d error code\n", ret);
        free(script);
        free(program);
        free(assetBlindingKey);
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
char *getAddressFromScript(const char *script_hex) {
    unsigned char *script;
    unsigned char *program;
    char *address = NULL;
    size_t script_len;
    size_t written;
    int ret;
    int isP2WSH;

    // convert script pubkey to bytes
    if (!(script = convertHexToBytes(script_hex, &script_len))) {
        printf("convertHexToBytes failed\n");
        return 0;
    }

    // get the program from the script
    if (!(program = getWitnessProgram(script, script_len, &isP2WSH))) {
        printf("getWitnessProgram failed\n");
        return 0;
    }

    // create the unconfidential address from program
    if ((ret = wally_addr_segwit_from_bytes(program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN, 
                                            UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 
                                            0, 
                                            &address)) != 0) {
        printf("wally_addr_segwit_from_bytes failed with %d error code\n", ret);
        free(script);
        free(program);
        return 0;
    }

    free(script);
    free(program);

    return address;
}

EMSCRIPTEN_KEEPALIVE
char *getConfidentialAddressFromAddress(const char *address, const char *blindingPrivkey_hex) {
    unsigned char *blindingPrivkey;
    unsigned char blindingPubkey[EC_PUBLIC_KEY_LEN];
    char *confidentialAddress;
    int ret;
    size_t privkey_len;

    // convert private key to bytes
    if (!(blindingPrivkey = convertHexToBytes(blindingPrivkey_hex, &privkey_len))) {
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
    int ret;

    if ((child = getChildFromXpub(xpub, hdPath, path_len)) == NULL) {
        printf("getChildFromXpub failed\n");
        return "";
    }

    memcpy(pubkey, child->pub_key, EC_PUBLIC_KEY_LEN);

    bip32_key_free(child);

    if ((ret = wally_hex_from_bytes(pubkey, EC_PUBLIC_KEY_LEN, &pubkey_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return "";
    }

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


EMSCRIPTEN_KEEPALIVE
char *createBlindedTransactionWithNewAsset(const char *prevTx_hex, const char *contractHash_hex, const char *masterBlindingKey_hex, const char *assetCAddress, const char *changeCAddress) {
    unsigned char *masterBlindingKey;
    size_t key_len;
    struct wally_tx *prevTx;
    unsigned char prevTxID[WALLY_TXHASH_LEN];
    struct blindingInfo *spentUTXOInput = NULL;
    struct wally_tx *newTx = NULL;
    char *newTx_hex = NULL;
    unsigned char newAssetID[SHA256_LEN];
    unsigned char *reversed_contractHash = NULL;
    size_t contractHash_len;
    int ret = 1;
    size_t written;

    // convert hex master blinding key to bytes
    if (!(masterBlindingKey = convertHexToBytes(masterBlindingKey_hex, &key_len))) {
        printf("convertHexToBytes failed\n");
        goto cleanup;
    }

    // convert hex tx to struct
    if ((ret = wally_tx_from_hex(prevTx_hex, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &prevTx)) != 0) {
        printf("wally_tx_from_hex failed with %d error code\n", ret);
        goto cleanup;
    }

    // get previous txid
    if ((ret = wally_tx_get_txid(prevTx, prevTxID, WALLY_TXHASH_LEN)) != 0) {
        printf("wally_tx_get_txid failed with %d error code\n", ret);
        goto cleanup;
    }
    
    // we loop on each output until we find one we can unblind with our keys
    for (size_t i = 0; i < (prevTx->num_outputs); i++) { // num_outputs should be either 1 or 2 for now, no fee output
        printf("Attempting to unblind output %zu\n", i);
        spentUTXOInput = unblindTxOutput(&(prevTx->outputs[i]), masterBlindingKey);
        if (!spentUTXOInput) {
            printf("unblindTxOutput failed\n");
            continue;
        }
        spentUTXOInput->vout = i; // should be either 0 or 1 for now
        spentUTXOInput->isInput = 1; // Since this will be our transaction's input, set isInput to 1
        if (generateAssetGenerator(spentUTXOInput)) { // we need to compute the asset generator for later use
            printf("generateAssetGenerator failed\n");
            goto cleanup;
        }
        break;
    }

    if (!spentUTXOInput) {
        printf("Found no output that can be unblinded in previous transaction. Aborting.\n");
        goto cleanup;
    }

    // the contract hash must be 32 bytes, so 64 char in hex string 
    if (strlen(contractHash_hex) != (SHA256_LEN * 2)) {
        printf("Provided contract hash is not 32B long\n");
        goto cleanup;
    }

    // reverse the contract hash bytes sequence (don't forget to free it)
    if (!(reversed_contractHash = reversedBytesFromHex(contractHash_hex, &contractHash_len))) {
        printf("reversedBytesFromHex failed for contract hash\n");
        goto cleanup;
    }

    // get new asset id
    if (getNewAssetID(prevTxID, spentUTXOInput->vout, reversed_contractHash, newAssetID) != 0) {
        printf("Failed getNewAssetID\n");
        goto cleanup;
    }

    // initialize all the blindingInfo we'll need
    if (populateBlindingInfoForProposalTx(spentUTXOInput, newAssetID, assetCAddress, changeCAddress) != 0) {
        printf("Failed to populate blinding infos\n");
        goto cleanup;
    }

    // create a new empty transaction and fill it
    wally_tx_init_alloc(2, 0, 0, 0, &newTx);

    // create and add the outputs
    if ((ret = addBlindedOutputs(newTx, spentUTXOInput)) != 0) {
        printf("addBlindedOutputs failed\n");
        goto cleanup;
    }

    // add asset issuance
    if ((ret = addIssuanceInput(newTx, spentUTXOInput, prevTxID, reversed_contractHash, masterBlindingKey)) != 0) {
        printf("addIssuanceInput failed\n");
        goto cleanup;
    }

    // get the tx in hex form
    if ((ret = wally_tx_to_hex(newTx, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &newTx_hex)) != 0) {
        printf("wally_tx_to_hex failed with %d error code\n", ret);
        goto cleanup;
    }


cleanup:
    freeBlindingInfo(&spentUTXOInput);
    clearThenFree(reversed_contractHash, contractHash_len);
    clearThenFree(masterBlindingKey, key_len);
    wally_tx_free(newTx);
    wally_tx_free(prevTx);

    return newTx_hex;
}

EMSCRIPTEN_KEEPALIVE
int txIsValid(const char *tx_hex) {
    int ret = 1;
    struct wally_tx *prev_tx;

    // convert hex tx to struct
    if ((ret = wally_tx_from_hex(tx_hex, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &prev_tx)) != 0) {
        printf("wally_tx_from_hex failed with %d error code\n", ret);
    }

    return ret;
}
