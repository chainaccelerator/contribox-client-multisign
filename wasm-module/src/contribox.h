#ifndef CONTRIBOX_H
#define CONTRIBOX_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "emscripten.h"

#include "../libwally/include/wally_address.h"
#include "../libwally/include/wally_bip32.h"
#include "../libwally/include/wally_bip38.h"
#include "../libwally/include/wally_bip39.h"
#include "../libwally/include/wally_core.h"
#include "../libwally/include/wally_crypto.h"
#include "../libwally/include/wally_elements.h"
#include "../libwally/include/wally_psbt.h"
#include "../libwally/include/wally_script.h"
#include "../libwally/include/wally_symmetric.h"
#include "../libwally/include/wally_transaction.h"

#define UNCONFIDENTIAL_ADDRESS_LIQUID_V1 "ex"
#define UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST "ert"

#define CONFIDENTIAL_ADDRESS_LIQUID_V1 "lq"
#define CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST "el"

#define BITCOIN_MAGIC "Bitcoin Signed Message:\n"

#define ISSUANCE_ASSET_AMT (unsigned long long)1
#define ISSUANCE_TOKEN_AMT (unsigned long long)0

#define IS_P2WSH 1
#define IS_P2WPKH 0

#define INPUT_DEACTIVATE_SEQUENCE (uint32_t)0xffffffff

#define KEY_SEARCH_DEPTH (size_t)20

#define MEMORY_ERROR "memory allocation error\n"

struct txInfo {
    size_t isInput;                                                // if 1, the struct is relative to an input; otherwise it's an output
    size_t isNewAsset;                                             // 1 if the asset newly generated ; otherwise it is an asset that is spent from previous UTXO
    unsigned char prevTxID[WALLY_TXHASH_LEN];                      // used only if isInput == 1 and isNewAsset == 0. Disregard it otherwise
    size_t vout;                                                   // the vout of the previous UTXO, used only if isInput == 1 and isNewAsset == 0. Disregard it otherwise
    unsigned char clearAsset[WALLY_TX_ASSET_CT_ASSET_LEN];         // '\1' + 32B asset tag. We can trim the first byte in case we only need the 32B tag
    uint64_t satoshi;                                              // value in satoshis. We won't necessarily need it
    unsigned char clearValue[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN]; // value obtained with wally_tx_confidential_value_from_satoshi()

    // for outputs only
    unsigned char *scriptPubkey;
    size_t scriptPubkey_len;
    char *address;

    struct txInfo *next;
};

// util.c
void            clearThenFree(void *p, size_t len);
void            freeTxInfo(struct txInfo **initialInput);
struct txInfo   *initTxInfo();

/** Fill an array of array_len size with random bytes
*   THIS IS NOT CRYPTOGRAPHICALLY SECURE, we use the rand() function
*   Use this function to generate randomness that is somewhat less critical, blinding factors and initialzation vector for AES encryption.
*   We use the browser PRNG for seed generation.
*   FIXME: either use the PRNG of the browser (a bit cumbersome), or add another dependency (libsodium?) with a proper PRNG.
**/
void            getRandomBytes(unsigned char *array, const size_t array_len);

/*  allocate and return a new byte string that contains the same byte sequence in reverse order
bitcoin and elements do love to reverse bytes sequence like hashes
BE CAREFUL */
void            *reverseBytes(const unsigned char *bytes, const size_t bytes_len);

unsigned char   *convertHexToBytes(const char *hexstring, size_t *bytes_len);

/** This is useful if we need to input some data that are usually printed out in reverse order by bitcoin/elements
*   like usually are the txid, asset id, and other hashes.
**/
unsigned char   *reversedBytesFromHex(const char *hexString, size_t *bytes_len);
void            printBytesInHex(const unsigned char *toPrint, const size_t len, const char *label);

/** this can be useful when we need to print out values that are usually printed in reverse by bitcoin/elements */
void            printBytesInHexReversed(const unsigned char *toPrint, const size_t len, const char *label);
uint32_t        *parseHdPath(const char *stringPath, size_t *path_len);
struct ext_key  *getChildFromXprv(const char *xprv, const uint32_t *hdPath, const size_t path_len);
struct ext_key  *getChildFromXpub(const char *xpub, const uint32_t *hdPath, const size_t path_len);

// script.c
unsigned char   *getWitnessProgram(const unsigned char *script, const size_t script_len, int *isP2WSH);
char            *getSegwitAddressFromScript(const unsigned char *script, const size_t script_len);
char            *getP2pkhFromPubkey(const unsigned char *pubkey);

// issuance.c
int getNewAssetID(const unsigned char *txID, const uint32_t vout, const unsigned char *reversed_contractHash, unsigned char *newAssetID);
int addIssuanceInput(struct wally_tx *newTx, struct txInfo *initialInput, const unsigned char *contractHash);

// transaction.c
int addOutputToTx(struct wally_tx *tx, const char *address, const size_t isP2WSH, const size_t amount, const unsigned char *asset);
int addInputToTx(struct wally_tx *tx, const unsigned char *prevTxID, const unsigned char *contractHash);

// signature.c
/** sign a message which must be a sha256 hash (32B long) with provided key **/
int signMessageECDSA(const unsigned char *signingKey, const unsigned char *toSign, unsigned char *derSig, size_t *written);
int verifyMessageECDSA(const unsigned char *pubkey, const unsigned char *hash, const unsigned char *sig);
int signTransactionECDSA(const unsigned char *signingKey, const unsigned char *toSign, unsigned char *derSig, size_t *written);

// crypto.c
unsigned char   *encryptWithAes(const char *toEncrypt, const unsigned char *key, size_t *cipher_len);
char            *decryptWithAes(const char *toDecrypt, const unsigned char *key);

#endif /*CONTRIBOX_H*/