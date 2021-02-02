#ifndef CONTRIBOX_H
#define CONTRIBOX_H

#include <string.h>
#include <stdio.h>
#include <time.h>
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

#define MEMORY_ERROR "memory allocation error\n"

struct blindingInfo {
    size_t              isInput; // if 1, the struct is relative to an input; otherwise it's an output
    size_t              isNewAsset; // 1 if the asset newly generated
    size_t              vout; // the vout of the previous UTXO, used only if isInput == 1 and isNewAsset == 0. Disregard it otherwise
    unsigned char       *clearAsset; 
    unsigned char       *assetBlindingFactor;
    unsigned char       *valueBlindingFactor;
    uint64_t            clearValue;
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
    unsigned char       nonce[EC_PUBLIC_KEY_LEN]; // this is the pubkey for the ephemeral privkey used for blinding an output, and not to be confused with nonce_hash

    struct blindingInfo *next;
};

void clearThenFree(void *p, size_t len);
void freeBlindingInfo(struct blindingInfo **initialInput);
struct blindingInfo *initBlindingInfo();
void    getRandomBytes(unsigned char *array, const size_t array_len);
void *reverseBytes(const unsigned char *bytes, const size_t bytes_len);
unsigned char *convertHexToBytes(const char *hexstring, size_t *bytes_len);
unsigned char *reversedBytesFromHex(const char *hexString, size_t *bytes_len);
void    printBytesInHex(const unsigned char *toPrint, const size_t len, const char *label);
unsigned char *getWitnessProgram(const unsigned char *script, const size_t script_len, int *isP2WSH);
int analyzeCAddress(const char *CAddress, char *address, unsigned char blindingPubkey[EC_PUBLIC_KEY_LEN], unsigned char *scriptPubkey, size_t scriptPubkey_len);
struct blindingInfo *unblindTxOutput(const struct wally_tx_output *output, const unsigned char *masterBlindingKey);
int getNewAssetID(const unsigned char *txID, const uint32_t vout, const unsigned char *reversed_contractHash, unsigned char *newAssetID);
unsigned long long *getValuesList(const struct blindingInfo *initialInput, size_t *values_len, size_t *num_inputs);
unsigned char *getAbfArray(const struct blindingInfo *initialInput, const size_t values_len);
unsigned char *getVbfArray(const struct blindingInfo *initialInput, const size_t values_len);
int getLastVbf(const struct blindingInfo *initialInput, unsigned char *lastVbf);
void    addBlindingInfoToList(struct blindingInfo *firstInput, struct blindingInfo *new);
int generateAssetGenerator(struct blindingInfo *element);
int generateValueCommitment(struct blindingInfo *element);
int blindOutputs(struct blindingInfo *initialInput);
int populateBlindingInfoForProposalTx(struct blindingInfo *initialInput, const unsigned char *newAssetID, const char *assetCAddress, const char *changeCAddress);
int addBlindedOutputs(struct wally_tx *newTx, struct blindingInfo *initialInput);
int getIssuanceNonce(const unsigned char *prevTxID, const uint32_t *index, const unsigned char *masterBlindingKey, unsigned char *nonce);
int addIssuanceInput(struct wally_tx *newTx, struct blindingInfo *initialInput, const unsigned char *prevTxID, const unsigned char *contractHash, const unsigned char *masterBlindingKey);

#endif /*CONTRIBOX_H*/