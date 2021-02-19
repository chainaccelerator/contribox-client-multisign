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

#define ISSUANCE_ASSET_AMT (unsigned long long)1
#define ISSUANCE_TOKEN_AMT (unsigned long long)0

#define INPUT_DEACTIVATE_SEQUENCE (uint32_t)0xffffffff

#define KEY_SEARCH_DEPTH (size_t)20

#define MEMORY_ERROR "memory allocation error\n"

struct txInfo {
    size_t              isInput; // if 1, the struct is relative to an input; otherwise it's an output
    size_t              isNewAsset; // 1 if the asset newly generated ; otherwise it is an asset that is spent from previous UTXO
    unsigned char       prevTxID[WALLY_TXHASH_LEN]; // used only if isInput == 1 and isNewAsset == 0. Disregard it otherwise
    size_t              vout; // the vout of the previous UTXO, used only if isInput == 1 and isNewAsset == 0. Disregard it otherwise
    unsigned char       clearAsset[WALLY_TX_ASSET_CT_ASSET_LEN]; // '\1' + 32B asset tag. We can trim the first byte in case we only need the 32B tag
    uint64_t            satoshi; // value in satoshis. We won't necessarily need it
    unsigned char       clearValue[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN]; // value obtained with wally_tx_confidential_value_from_satoshi()

    // only if blinded transaction 
    unsigned char       masterBlindingKey[SHA512_LEN]; 
    unsigned char       *assetBlindingFactor;
    unsigned char       *valueBlindingFactor;
    unsigned char       generator[ASSET_GENERATOR_LEN];
    unsigned char       rangeproof[ASSET_RANGEPROOF_MAX_LEN];
    size_t              rangeproof_len; // this is the actual size written for the rangeproof
    unsigned char       valueCommitment[ASSET_COMMITMENT_LEN];

    // for outputs only
    unsigned char       *scriptPubkey;
    size_t              scriptPubkey_len;
    unsigned char       *surjectionproof;
    size_t              surjectionproof_len;
    char                *address; 
    unsigned char       blindingPubkey[EC_PUBLIC_KEY_LEN];
    unsigned char       nonce[EC_PUBLIC_KEY_LEN]; // this is the pubkey for the ephemeral privkey used for blinding an output. It's empty for first issuances

    struct txInfo *next;
};

void clearThenFree(void *p, size_t len);
void freeTxInfo(struct txInfo **initialInput);
struct txInfo *initTxInfo();

/** Fill an array of array_len size with random bytes
*   THIS IS NOT CRYPTOGRAPHICALLY SECURE, we use the rand() function
*   Use this function to generate randomness that is somewhat less critical, blinding factors and initialzation vector for AES encryption.
*   We use the browser PRNG for seed generation.
*   FIXME: either use the PRNG of the browser (a bit cumbersome), or add another dependency (libsodium?) with a proper PRNG.
**/
void    getRandomBytes(unsigned char *array, const size_t array_len);

/*  allocate and return a new byte string that contains the same byte sequence in reverse order
bitcoin and elements do love to reverse bytes sequence like hashes
BE CAREFUL */
void *reverseBytes(const unsigned char *bytes, const size_t bytes_len);

unsigned char *convertHexToBytes(const char *hexstring, size_t *bytes_len);

/** This is useful if we need to input some data that are usually printed out in reverse order by bitcoin/elements
*   like usually are the txid, asset id, and other hashes.
**/
unsigned char *reversedBytesFromHex(const char *hexString, size_t *bytes_len);
void    printBytesInHex(const unsigned char *toPrint, const size_t len, const char *label);

/** this can be useful when we need to print out values that are usually printed in reverse by bitcoin/elements */
void    printBytesInHexReversed(const unsigned char *toPrint, const size_t len, const char *label);
unsigned char *getWitnessProgram(const unsigned char *script, const size_t script_len, int *isP2WSH);
int analyzeCAddress(const char *CAddress, char *address, unsigned char blindingPubkey[EC_PUBLIC_KEY_LEN], unsigned char *scriptPubkey, size_t scriptPubkey_len);
struct txInfo *unblindTxOutput(const struct wally_tx_output *output, const unsigned char *masterBlindingKey);
int getNewAssetID(const unsigned char *txID, const uint32_t vout, const unsigned char *reversed_contractHash, unsigned char *newAssetID);
unsigned long long *getValuesList(const struct txInfo *initialInput, size_t *values_len, size_t *num_inputs);
unsigned char *getAbfArray(const struct txInfo *initialInput, const size_t values_len);
unsigned char *getVbfArray(const struct txInfo *initialInput, const size_t values_len);
int getLastVbf(const struct txInfo *initialInput, unsigned char *lastVbf);
void    addTxInfoToList(struct txInfo *firstInput, struct txInfo *new);
int generateAssetGenerator(struct txInfo *element);
int generateValueCommitment(struct txInfo *element);
int blindOutputs(struct txInfo *initialInput);

/*  populateTxInfoForProposalTx builds a linked list that starts with the UTXO we spend and add:
*   - an issuance input (wich is not really an input but can be considered one for blinding purpose)
*   - an output we will send the newly created asset to
*   - an output we will send the asset in the spent UTXO (change)
*   For each of these we need to set a few flags (isInput and isNewAsset) and to fill in some data:
*   - asset ID (either the one we have in the provided UTXO or the one we just created)
*   - a value in sat (will be `1` most of the time I think)
*   - an asset blinding factor and a value blinding factor (randomly generated, except the last value blinding factor)
*   - an asset generator (computed with a dedicated function in libwally)
*   For the outputs ONLY we also need to decompose the provided confidential addresses:
*   - a blinding pubkey (contained in the address)
*   - the scriptpubkey
*   - the unconfidential address 
**/
int populateTxInfoForProposalTx(struct txInfo *initialInput, const unsigned char *newAssetID, const char *assetCAddress, const char *changeCAddress);

/* Loop through all the txInfo we have for outputs and add outputs to a transaction */
int addBlindedOutputs(struct wally_tx *newTx, struct txInfo *initialInput);

/* Inspired from what is done in Elements, we create an OP_RETURN + prevout script and derive a key from it
* using the master blinding key. 
*/
int getIssuanceNonce(const unsigned char *prevTxID, uint32_t index, const unsigned char *masterBlindingKey, unsigned char *nonce);

int addIssuanceInput(struct wally_tx *newTx, struct txInfo *initialInput, const unsigned char *contractHash);
int addOutputToTx(struct wally_tx *tx, const char *address, const size_t isP2WSH, const size_t amount, const unsigned char *asset);
int addInputToTx(struct wally_tx *tx, const unsigned char *prevTxID, const unsigned char *contractHash);

#endif /*CONTRIBOX_H*/