#include "contribox.h"

int getNewAssetID(const unsigned char *txID, const uint32_t vout, const unsigned char *reversed_contractHash, unsigned char *newAssetID) {
    unsigned char entropy[SHA256_LEN];
    int ret;

    // get the entropy
    if ((ret = wally_tx_elements_issuance_generate_entropy(txID, WALLY_TXHASH_LEN,
                                                            vout,
                                                            reversed_contractHash, SHA256_LEN,
                                                            entropy, SHA256_LEN)) != 0) {
        printf("wally_tx_elements_issuance_generate_entropy failed with %d error code\n", ret);
        return ret;
    }

    // get the asset id
    if ((ret = wally_tx_elements_issuance_calculate_asset(entropy, SHA256_LEN, newAssetID, SHA256_LEN)) != 0) {
        printf("wally_tx_elements_issuance_calculate_asset failed with %d error code\n", ret);
        return ret;
    }

    return ret;
}

int addIssuanceInput(struct wally_tx *newTx, struct txInfo *initialInput, const unsigned char *contractHash) {
    /* complete the provided issuance input and add it to newTx */
    struct txInfo *issuance;
    uint32_t vout;
    unsigned char *prevTxID;
    int ret = 1;
    size_t written;

    // get the vout
    vout = (uint32_t)initialInput->vout;

    // get the prevTxID
    prevTxID = initialInput->prevTxID;

    // set temp to the issuance input 
    issuance = initialInput->next;

    if (!issuance->isInput || !issuance->isNewAsset) {
        printf("selected tx infos are not the issuance\n");
        return ret;
    }

    // add the input to the transaction
    ret = wally_tx_add_elements_raw_input(newTx,
                                            prevTxID, WALLY_TXHASH_LEN,
                                            vout | WALLY_TX_ISSUANCE_FLAG,
                                            INPUT_DEACTIVATE_SEQUENCE, // sequence must be set at 0xffffffff if not used
                                            NULL, 0, // scriptSig and its length
                                            NULL, // witness stack
                                            NULL, 0, // issuance has an empty nonce
                                            contractHash, WALLY_TX_ASSET_TAG_LEN, // the contract hash provided in input, only reversed
                                            issuance->clearValue, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN, // blinded issuance amount obtained with wally_asset_value_commitment()
                                            NULL, 0, // blinded token amount, this should be 0
                                            NULL, 0, // issuance rangeproof
                                            NULL, 0, // token rangeproof, since we don't have a token output we can just forget it for now
                                            NULL, // peginWitness, this should be NULL for non pegin transaction
                                            0); // flag, must be 0

    if (ret != 0) {
        printf("wally_tx_add_elements_raw_input failed with %d error code\n", ret);
        return ret;
    }

    return ret;
}
