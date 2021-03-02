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
char *hdKeyFromSeed(const char *seed_hex) {
    struct ext_key *hdKey;
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t written;
    int ret;
    char *xprv;

    wally_hex_to_bytes(seed_hex, seed, BIP39_SEED_LEN_512, &written);

    if ((ret = bip32_key_from_seed_alloc(seed, BIP39_SEED_LEN_512, BIP32_VER_TEST_PRIVATE, (uint32_t)0, &hdKey)) != 0) {
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
char *encryptStringWithPubkey(const char *pubkey_hex, const char *toEncrypt, unsigned char *ephemeralPrivkey) {
    unsigned char   *buffer = NULL;
    unsigned char   ephemeralPubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   key[SHA256_LEN];
    char            *encryptedFile = NULL;
    size_t          written;
    int             ret;

    // verify that provided entropy is a valid private key
    if ((ret = wally_ec_private_key_verify(ephemeralPrivkey, EC_PRIVATE_KEY_LEN))) {
        printf("wally_ec_private_key_verify failed with %d error code\n", ret);
        printf("Provided entropy can't be used as a private key, try again with another entropy\n");
        return NULL;
    }

    // get the public key
    if ((ret = wally_ec_public_key_from_private_key(ephemeralPrivkey, EC_PRIVATE_KEY_LEN, ephemeralPubkey, EC_PUBLIC_KEY_LEN))) {
        printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
        return NULL;
    }

    // convert the pubkey in bytes form
    if (!(buffer = convertHexToBytes(pubkey_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    memcpy(pubkey, buffer, written);

    clearThenFree(buffer, written);

    if (written != EC_PUBLIC_KEY_LEN) {
        printf("Provided hex is not a valid public key, it's %zu long\n", written);
        return NULL;
    }

    // get the shared secret with ECDH
    if ((ret = wally_ecdh(pubkey, EC_PUBLIC_KEY_LEN, ephemeralPrivkey, EC_PRIVATE_KEY_LEN, key, sizeof(key)))) {
        printf("wally_ecdh failed with %d error code\n", ret);
        return NULL;
    }

    if ((buffer = encryptWithAes(toEncrypt, key, &written)) == NULL) {
        printf("encryptWithAes failed\n");
        return NULL;
    }

    // erase all private material from memory
    memset(key, '\0', sizeof(key));
    memset(ephemeralPrivkey, '\0', EC_PRIVATE_KEY_LEN);

    if ((ret = wally_base58_from_bytes(buffer, written, BASE58_FLAG_CHECKSUM, &encryptedFile)) != 0) {
        printf("wally_base58_from_bytes failed\n");
    };

    clearThenFree(buffer, written);

    return encryptedFile;
}

EMSCRIPTEN_KEEPALIVE
char    *encryptStringWithPassword(const char *userPassword, const char *toEncrypt) {
    unsigned char   key[PBKDF2_HMAC_SHA256_LEN];
    unsigned char   *cipher = NULL;
    char            *encryptedFile = NULL;
    size_t          cipher_len;
    int             ret;

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
        return NULL;
    };

    if ((cipher = encryptWithAes(toEncrypt, key, &cipher_len)) == NULL) {
        printf("encryptWithAes failed\n");
        return NULL;
    }

    memset(key, '\0', sizeof(key));

    if ((ret = wally_base58_from_bytes(cipher, cipher_len, BASE58_FLAG_CHECKSUM, &encryptedFile)) != 0) {
        printf("wally_base58_from_bytes failed\n");
    };

    clearThenFree(cipher, cipher_len);

    return encryptedFile;
}

EMSCRIPTEN_KEEPALIVE
char    *pubkeyFromPrivkey(const char *privkey_hex) {
    unsigned char   *buffer = NULL;
    unsigned char   privkey[EC_PRIVATE_KEY_LEN];
    unsigned char   pubkey[EC_PUBLIC_KEY_LEN];
    char            *pubkey_hex = NULL;
    size_t          written;
    int             ret = 1;

    // get the signing key in bytes form
    if (!(buffer = convertHexToBytes(privkey_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    memcpy(privkey, buffer, sizeof(privkey));

    clearThenFree(buffer, written);

    if ((ret = wally_ec_public_key_from_private_key(privkey, EC_PRIVATE_KEY_LEN, pubkey, EC_PUBLIC_KEY_LEN))) {
        printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
        return NULL;
    }

    if ((ret = wally_hex_from_bytes(pubkey, sizeof(pubkey), &pubkey_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return NULL;
    }

    return pubkey_hex;
}

EMSCRIPTEN_KEEPALIVE
char    *addressFromPrivkey(const char *privkey_hex) {
    unsigned char   *buffer = NULL;
    unsigned char   privkey[EC_PRIVATE_KEY_LEN];
    char            *wif = NULL;
    char            *address = NULL;
    size_t          written;
    int             ret = 1;

    // get the signing key in bytes form
    if (!(buffer = convertHexToBytes(privkey_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    memcpy(privkey, buffer, sizeof(privkey));

    clearThenFree(buffer, written);

    // get the wif format
    if ((ret = wally_wif_from_bytes(privkey, EC_PRIVATE_KEY_LEN, WALLY_ADDRESS_VERSION_WIF_TESTNET, WALLY_WIF_FLAG_COMPRESSED, &wif))) {
        printf("wally_wif_from_bytes failed with %d error code\n", ret);
        return NULL;
    }

    // get the legacy address from wif
    if ((ret = wally_wif_to_address(wif, WALLY_ADDRESS_VERSION_WIF_TESTNET, WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST, &address))) {
        printf("wally_wif_to_address failed with %d error code\n", ret);
    }

    return address;
}

EMSCRIPTEN_KEEPALIVE
char *getAddressFromScript(const char *script_hex) {
    unsigned char *script = NULL;
    unsigned char *program = NULL;
    char *address = NULL;
    size_t script_len;
    int ret;
    int isP2WSH;

    // convert script pubkey to bytes
    if (!(script = convertHexToBytes(script_hex, &script_len))) {
        printf("convertHexToBytes failed\n");
        goto cleanup;
    }

    // get the program from the script
    if (!(program = getWitnessProgram(script, script_len, &isP2WSH))) {
        printf("getWitnessProgram failed\n");
        goto cleanup;
    }

    // create the unconfidential address from program
    if ((ret = wally_addr_segwit_from_bytes(program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN, 
                                            UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 
                                            0, 
                                            &address)) != 0) {
        printf("wally_addr_segwit_from_bytes failed with %d error code\n", ret);
    }

cleanup:
    clearThenFree(program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN);
    clearThenFree(script, script_len);

    return address;
}

EMSCRIPTEN_KEEPALIVE
char *getPrivkeyFromXprv(const char *xprv, const char *path, const size_t range) {
    struct ext_key *child;
    char *privkey_hex;
    char    *wif;
    unsigned char privkey[EC_PRIVATE_KEY_LEN];
    uint32_t    *hdPath;
    size_t      path_len;
    int ret;

    if ((hdPath = parseHdPath(path, &path_len)) == NULL) {
        printf("parseHdPath failed\n");
        return 0;
    }

    if (range > 0) {
        hdPath[path_len - 1] = (uint32_t)(rand() % range);
    } 

    if ((child = getChildFromXprv(xprv, hdPath, path_len)) == NULL) {
        printf("getChildFromXprv failed\n");
        return 0;
    }

    memcpy(privkey, (child->priv_key) + 1, EC_PRIVATE_KEY_LEN); // we skip the first byte which is a '\0' flag

    // printBytesInHex(privkey, sizeof(privkey), "privkey");

    bip32_key_free(child);
    free(hdPath);

    if ((ret = wally_hex_from_bytes(privkey, EC_PRIVATE_KEY_LEN, &privkey_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return 0;
    }

    memset(privkey, '\0', EC_PRIVATE_KEY_LEN);

    return privkey_hex;
}

EMSCRIPTEN_KEEPALIVE
char *getPubkeyFromXpub(const char *xpub, const char *path, const size_t range) {
    struct ext_key *child = NULL;
    char *pubkey_hex = NULL;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    uint32_t    *hdPath = NULL;
    size_t      path_len;
    int ret;

    if ((hdPath = parseHdPath(path, &path_len)) == NULL) {
        printf("parseHdPath failed\n");
        goto cleanup;
    }

    if (range > 0) {
        hdPath[path_len - 1] = (uint32_t)(rand() % range);
    } 

    if ((child = getChildFromXpub(xpub, hdPath, path_len)) == NULL) {
        printf("getChildFromXpub failed\n");
        goto cleanup;
    }

    memcpy(pubkey, child->pub_key, EC_PUBLIC_KEY_LEN);

    if ((ret = wally_hex_from_bytes(pubkey, EC_PUBLIC_KEY_LEN, &pubkey_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
    }

cleanup:
    bip32_key_free(child);
    if (hdPath)
        free(hdPath);

    return pubkey_hex;
}

EMSCRIPTEN_KEEPALIVE
char *getPubkeyFromXprv(const char *xprv, const char *path, const size_t range) {
    struct ext_key *child;
    char *pubkey_hex;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    uint32_t    *hdPath;
    size_t      path_len;
    int ret;

    if ((hdPath = parseHdPath(path, &path_len)) == NULL) {
        printf("parseHdPath failed\n");
        return "";
    }

    if (range > 0) {
        hdPath[path_len - 1] = (uint32_t)(rand() % range);
    } 

    if ((child = getChildFromXprv(xprv, hdPath, path_len)) == NULL) {
        printf("getChildFromXprv failed\n");
        return "";
    }

    memcpy(pubkey, child->pub_key, EC_PUBLIC_KEY_LEN);

    bip32_key_free(child);
    free(hdPath);

    if ((ret = wally_hex_from_bytes(pubkey, EC_PUBLIC_KEY_LEN, &pubkey_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return "";
    }

    return pubkey_hex;
}

EMSCRIPTEN_KEEPALIVE
char *getAddressFromXpub(const char *xpub, const char *path, const size_t range) {
    struct ext_key *child;
    char *address;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    uint32_t    *hdPath;
    size_t      path_len;
    int ret;

    if ((hdPath = parseHdPath(path, &path_len)) == NULL) {
        printf("parseHdPath failed\n");
        return "";
    }

    if (range > 0) {
        hdPath[path_len - 1] = (uint32_t)(rand() % range);
    } 

    if ((child = getChildFromXpub(xpub, hdPath, path_len)) == NULL) {
        printf("getChildFromXpub failed\n");
        return "";
    }

    if ((ret = wally_bip32_key_to_addr_segwit(child, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, (uint32_t)0, &address)) != 0) {
        printf("wally_bip32_key_to_addr_segwit failed with %d error code\n", ret);
        return "";
    }

    bip32_key_free(child);
    free(hdPath);

    return address;
}

char *createUnconfidentialTransactionWithNewAsset(struct txInfo *initialInput, const unsigned char *newAssetID, const unsigned char *reversed_contractHash, const char *assetAddress, const char *changeAddress) {
    unsigned char changeAsset[WALLY_TX_ASSET_CT_ASSET_LEN]; 
    unsigned char newAsset[WALLY_TX_ASSET_CT_ASSET_LEN]; 
    struct wally_tx *newTx = NULL;
    char *newTx_hex = NULL;
    int ret;
    size_t written;

    // copy the new asset ID with a leading '\1'
    memcpy(newAsset, "\1", 1); // we add a '\1' byte before the asset tag
    memcpy(newAsset + 1, newAssetID, ASSET_TAG_LEN);

    // copy the spent asset
    memcpy(changeAsset, initialInput->clearAsset, WALLY_TX_ASSET_CT_ASSET_LEN);

    // create a new empty transaction and fill it
    wally_tx_init_alloc(2, 0, 0, 0, &newTx);

    // add the change output to the tx
    if ((ret = addOutputToTx(newTx, changeAddress, IS_P2WPKH, initialInput->satoshi, changeAsset)) != 0) {
        printf("addOutputToTx failed for change output\n");
        goto cleanup;
    }

    // add the new asset output to the tx
    if ((ret = addOutputToTx(newTx, assetAddress, IS_P2WPKH, ISSUANCE_ASSET_AMT, newAsset)) != 0) {
        printf("addOutputToTx failed for new asset output\n");
        goto cleanup;
    }

    // add the input including the unblinded issuance
    if ((ret = addInputToTx(newTx, initialInput->prevTxID, reversed_contractHash)) != 0) {
        printf("addInputToTx failed for input\n");
        goto cleanup;
    }

    // get the tx in hex form
    if ((ret = wally_tx_to_hex(newTx, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_ALLOW_PARTIAL, &newTx_hex)) != 0) {
        printf("wally_tx_to_hex failed with %d error code\n", ret);
    }

cleanup:
    wally_tx_free(newTx);

    return newTx_hex;
}


EMSCRIPTEN_KEEPALIVE
char *createTransactionWithNewAsset(const char *prevTx_hex, const char *contractHash_hex, const char *assetAddress, const char *changeAddress) {
    size_t key_len;
    struct wally_tx *prevTx;
    struct txInfo *spentUTXOInput = NULL;
    struct wally_tx *newTx = NULL;
    char *newTx_hex = NULL;
    unsigned char newAssetID[SHA256_LEN];
    unsigned char *reversed_contractHash = NULL;
    size_t contractHash_len;
    int ret = 1;
    size_t written;

    printf("assetAddress is %s\n", assetAddress);

    // convert hex prevTx to struct
    if ((ret = wally_tx_from_hex(prevTx_hex, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &prevTx)) != 0) {
        printf("wally_tx_from_hex failed with %d error code\n", ret);
        goto cleanup;
    }

    if (!(spentUTXOInput = initTxInfo())) {
        printf("Failed to initialize txInfo struct\n");
        goto cleanup; 
    }

    memcpy(spentUTXOInput->clearValue, prevTx->outputs[0].value, prevTx->outputs[0].value_len); // len must be 9 for unblinded value
    if ((ret = wally_tx_confidential_value_to_satoshi(spentUTXOInput->clearValue, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN, &(spentUTXOInput->satoshi))) != 0) {
        printf("wally_tx_confidential_value_to_satoshi failed with %d error\n", ret);
        goto cleanup;
    }
    memcpy(spentUTXOInput->clearAsset, prevTx->outputs[0].asset, prevTx->outputs[0].asset_len);

    spentUTXOInput->isInput = 1; // Since this will be our transaction's input, set isInput to 1

    // get previous txid
    if ((ret = wally_tx_get_txid(prevTx, spentUTXOInput->prevTxID, WALLY_TXHASH_LEN)) != 0) {
        printf("wally_tx_get_txid failed with %d error code\n", ret);
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
    if (getNewAssetID(spentUTXOInput->prevTxID, spentUTXOInput->vout, reversed_contractHash, newAssetID) != 0) {
        printf("Failed getNewAssetID\n");
        goto cleanup;
    }

    newTx_hex = createUnconfidentialTransactionWithNewAsset(spentUTXOInput, newAssetID, reversed_contractHash, assetAddress, changeAddress);

cleanup:
    freeTxInfo(&spentUTXOInput);
    clearThenFree(reversed_contractHash, contractHash_len);
    wally_tx_free(prevTx);

    return newTx_hex;
}

EMSCRIPTEN_KEEPALIVE
char    *getSigningKey(const char *xprv, const char *address, const char *path, const size_t range) {
    unsigned char   scriptPubkey[WALLY_SCRIPTPUBKEY_P2WPKH_LEN]; // we take the risk of a stack overflow here, but maybe it's okay since the function will fail immediately anyway 
    unsigned char   keyHash[HASH160_LEN];
    uint32_t        *hdPath;
    size_t          path_len;
    struct ext_key  *childKey = NULL;
    unsigned char   candidateHash[HASH160_LEN];
    char            *wif;
    char            *signingKey_hex = NULL;
    size_t          limit = 0;
    int             ret = 1;
    size_t          written;

    // get the hash of the pubkey we're looking for from the address
    if (!(strncmp(address, CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 2))) { // address is confidential
        // TODO: extract the unconfidential address from confidential address instead of letting the user do the job
        printf("Provided address is confidential, need an unconfidential address\n");
        return NULL;
    } else {
        // get the script pubkey corresponding to the address
        ret = wally_addr_segwit_to_bytes(address, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 0, scriptPubkey, sizeof(scriptPubkey), &written);
        if (ret != 0) {
            printf("wally_addr_segwit_to_bytes failed with %d error code\n", ret);
            return NULL;
        }

        if (written != WALLY_SCRIPTPUBKEY_P2WPKH_LEN) {
            printf("Provided address is not P2WPKH, scriptPubkey length is %zu\nShould be %d\n", written,WALLY_SCRIPTPUBKEY_P2WPKH_LEN);
            return NULL;
        }

        // get the hash of the key from the scriptPubkey
        memcpy(keyHash, scriptPubkey + 2, HASH160_LEN); // skip the segwit version + varint byte
        printBytesInHex(keyHash, HASH160_LEN, "keyHash");
    }

    if ((hdPath = parseHdPath(path, &path_len)) == NULL) {
        printf("parseHdPath failed\n");
        return NULL;
    }

    limit = hdPath[path_len - 1] + range;

    for (size_t i = hdPath[path_len - 1]; i < limit; i++) {
        // free childKey, if necessary
        if (childKey)
            bip32_key_free(childKey);

        // update the last index in path
        hdPath[path_len - 1] = i;

        // get the child key from xprv
        childKey = getChildFromXprv(xprv, hdPath, path_len);
        if (!childKey) {
            printf("getChildFromXprv failed\n");
            return NULL;
        }

        // hash the candidate pubkey
        wally_hash160(childKey->pub_key, EC_PUBLIC_KEY_LEN, candidateHash, HASH160_LEN);

        // compare the pubkeys, if they're the same, then the privkey is the signing key we're returning
        if (!memcmp(candidateHash, keyHash, HASH160_LEN)) {
            if ((ret = wally_hex_from_bytes(childKey->priv_key + 1, EC_PRIVATE_KEY_LEN, &signingKey_hex)) != 0) {
                printf("wally_hex_from_bytes failed with %d error code\n", ret);
            }
            break;
        } else {
            continue;
        }
    }

    bip32_key_free(childKey);

    return signingKey_hex;
}

EMSCRIPTEN_KEEPALIVE
char    *createMessageToSign(const char *string) {
    unsigned char   format[SHA256_LEN];
    char            *message = NULL;
    size_t          written;
    int             ret = 1;

    // format the message 
    if ((ret = wally_format_bitcoin_message((unsigned char *)string, strlen(string), BITCOIN_MESSAGE_FLAG_HASH, format, sizeof(format), &written))) {
        printf("wally_format_bitcoin_message failed with %d error code\n", ret);
        return NULL;
    }
    
    if ((ret = wally_hex_from_bytes(format, written, &message))) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
    }

    return message;
}

EMSCRIPTEN_KEEPALIVE
char    *signHashWithKey(const char *signingKey_hex, const char *hash_hex) {
    unsigned char   *temp = NULL;
    unsigned char   signingKey[EC_PRIVATE_KEY_LEN];
    unsigned char   toSign[EC_MESSAGE_HASH_LEN];
    unsigned char   derSig[EC_SIGNATURE_DER_MAX_LEN];
    char            *derSig_64 = NULL;
    size_t          written;
    int             ret = 1;

    // get the bytes from the hex
    if (!(temp = convertHexToBytes(hash_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    // check that the byte array we got is of the right length
    if (written != EC_MESSAGE_HASH_LEN) {
        printf("provided hash hex must be %d, not %zu\n", EC_MESSAGE_HASH_LEN * 2, written * 2);
        clearThenFree(temp, written);
        return NULL;
    }

    memcpy(toSign, temp, written);
    clearThenFree(temp, written);

    // get the bytes of signing key
    if (!(temp = convertHexToBytes(signingKey_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }
    memcpy(signingKey, temp, written);
    clearThenFree(temp, written);

    // sign the hash with the provided key
    if (signMessageECDSA(signingKey, toSign, derSig, &written)) {
        printf("signMessageECDSA failed\n");
        return NULL;
    }

    // convert the der signature to hex string 
    if ((ret = wally_base64_from_bytes(derSig, written, 0, &derSig_64)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return NULL;
    }

    return derSig_64;
}

EMSCRIPTEN_KEEPALIVE
int verifySignatureWithAddress(const char *address, const char *string, const char *sig_64) {
    unsigned char   format[EC_MESSAGE_HASH_LEN];
    unsigned char   sig[EC_SIGNATURE_RECOVERABLE_LEN];
    size_t          sig_len;
    unsigned char   pubkey[EC_PUBLIC_KEY_LEN];
    char            *recoveredAddress = NULL;
    size_t          written;
    int             ret = 1;

    printf("provided signature in base64 is %s\n", sig_64);
    printf("message being verified is %s\n", string);
    printf("address is %s\n", address);
    // get the size of the decoded base 64 der signature
    if ((ret = wally_base64_get_maximum_length(sig_64, 0, &sig_len))) {
        printf("wally_base64_get_maximum_length failed with %d error code\n", ret);
        return ret;
    }

    // get the compact signature
    if ((ret = wally_base64_to_bytes(sig_64, 0, sig, sig_len, &written))) {
        printf("wally_base64_to_bytes failed with %d error code\n", ret);
        return ret;
    }

    // get the formated message that was signed
    if ((ret = wally_format_bitcoin_message((unsigned char *)string, strlen(string), BITCOIN_MESSAGE_FLAG_HASH, format, sizeof(format), &written))) {
        printf("wally_format_bitcoin_message failed with %d error code\n", ret);
        return ret;
    }

    // recover the pubkey from the signature
    if ((ret = wally_ec_sig_to_public_key(format, sizeof(format), sig, sizeof(sig), pubkey, sizeof(pubkey)))) {
        printf("wally_ec_sig_to_public_key failed with %d error code\n", ret);
        return ret;
    }

    // get the address from the recovered pubkey
    if (!(recoveredAddress = P2pkhFromPubkey(pubkey))) {
        printf("P2pkhFromPubkey failed\n");
        return 1;
    }

    // compare the address and the over we just recovered from the signature
    if ((ret = strncmp(address, recoveredAddress, strlen(address)))) {
        printf("Invalid signature for this message\n");
        return ret;
    }

    clearThenFree(recoveredAddress, strlen(recoveredAddress));

    return ret;
}

EMSCRIPTEN_KEEPALIVE
char    *signProposalTx(const char *unsignedTx, const char *signingKey_hex) {
    unsigned char                   *buffer = NULL;
    char                            *signedTx = NULL; 
    struct wally_tx                 *tempTx = NULL; 
    unsigned char                   signingKey[EC_PRIVATE_KEY_LEN];
    unsigned char                   pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char                   scriptCode[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    unsigned char                   sighash[SHA256_LEN];
    unsigned char                   derSig[EC_SIGNATURE_DER_MAX_LOW_R_LEN + 1]; // we need one byte for SIGHASH
    char                            *derSig_hex = NULL;
    struct wally_tx_witness_stack   *witnessStack = NULL;
    size_t                          written = 0;
    int                             ret = 1;

    // convert hex tx to struct
    if ((ret = wally_tx_from_hex(unsignedTx, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &tempTx)) != 0) {
        printf("wally_tx_from_hex failed with %d error code\n", ret);
        return NULL;
    }

    // get the signing key in bytes form
    if (!(buffer = convertHexToBytes(signingKey_hex, &written))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    memcpy(signingKey, buffer, sizeof(signingKey));

    clearThenFree(buffer, written);

    // we need the scriptCode, which is basically the script that will be executed, to compute the scriptHash that will be signed
    // first the pubkey
    if ((ret = wally_ec_public_key_from_private_key(signingKey, EC_PRIVATE_KEY_LEN, pubkey, EC_PUBLIC_KEY_LEN)) != 0) {
        printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
        goto cleanup;
    }

    // construct the Script, here a standard P2PKH
    if ((ret = wally_scriptpubkey_p2pkh_from_bytes(pubkey, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, scriptCode, WALLY_SCRIPTPUBKEY_P2PKH_LEN, &written)) != 0) {
        printf("wally_scriptpubkey_p2pkh_from_bytes failed with %d error code\n", ret);
        goto cleanup;
    }

    // now we can produce the sighash
    if ((ret = wally_tx_get_elements_signature_hash(tempTx, 
                                                    0, // index that we are signing. Will always be 0 for now
                                                    scriptCode, sizeof(scriptCode),
                                                    tempTx->outputs[0].value, tempTx->outputs[0].value_len, // we know that output 0 is the sender paying himself back, so we can get the amount spent from here (will be 1 most of the time)
                                                    WALLY_SIGHASH_ALL,
                                                    WALLY_TX_FLAG_USE_WITNESS,
                                                    sighash, SHA256_LEN)) != 0) {
        printf("wally_tx_get_elements_signature_hash failed with %d error code\n", ret);
        goto cleanup;
    }

    // and finally create the signature
    if ((signTransactionECDSA(signingKey, sighash, derSig, &written))) {
        printf("signTransactionECDSA failed\n");
        goto cleanup;
    }

    derSig[written] = WALLY_SIGHASH_ALL; // we add the sighash byte after the der signature

    // now we add the pubkey and signature to witness stack
    if ((ret = wally_tx_witness_stack_init_alloc(0, &witnessStack)) != 0) {
        printf(MEMORY_ERROR);
        goto cleanup;
    }

    if ((ret = wally_tx_witness_stack_add(witnessStack, derSig, written + 1)) ||
        (ret = wally_tx_witness_stack_add(witnessStack, pubkey, EC_PUBLIC_KEY_LEN))) {
        printf("wally_tx_witness_stack_add failed with %d error code\n", ret);
        goto cleanup;
    }

    if ((ret = wally_tx_set_input_witness(tempTx, 0, witnessStack))) {
        printf("wally_tx_set_input_witness failed with %d error code\n", ret);
        goto cleanup;
    }

    // at last we can return the hex serialized transaction
    if ((ret = wally_tx_to_hex(tempTx, WALLY_TX_FLAG_USE_ELEMENTS | WALLY_TX_FLAG_USE_WITNESS, &signedTx)) != 0) {
        printf("wally_tx_to_hex failed with %d error code\n", ret);
    }

cleanup:
    wally_tx_witness_stack_free(witnessStack);

    return signedTx;
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
