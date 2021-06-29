#include "contribox.h"

int addOutputToTx(struct wally_tx *tx, const char *address, const size_t amount, const unsigned char *asset) {
    unsigned char *scriptPubkey;
    size_t scriptPubkey_len;
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    size_t written;
    int ret = 1;

    if (strlen(address) == 63) {
        printf("address is P2WSH\n");
        scriptPubkey_len = WALLY_SCRIPTPUBKEY_P2WSH_LEN;
    } else if (strlen(address) == 43) {
        printf("address is P2WPKH\n");
        scriptPubkey_len = WALLY_SCRIPTPUBKEY_P2WPKH_LEN;
    } else {
        fprintf(stderr, "Address is %zu characters long. Must be either 43 or 63\n", strlen(address));
        goto cleanup;
    }

    if (!(scriptPubkey = calloc(scriptPubkey_len, sizeof(*scriptPubkey)))) {
        printf(MEMORY_ERROR);
        goto cleanup;
    }

    // get the script pubkey corresponding to the destination address
    ret = wally_addr_segwit_to_bytes(address, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 0, scriptPubkey, scriptPubkey_len, &written);
    if (ret != 0) {
        printf("wally_addr_segwit_to_bytes failed with %d error code\n", ret);
        goto cleanup;
    }

    // get the unblinded confidential value from amount in satoshis
    if ((ret = wally_tx_confidential_value_from_satoshi((uint64_t)amount, value, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)) != 0) {
        printf("wally_tx_confidential_value_from_satoshi failed with %d error code\n", ret);
        goto cleanup;
    }

    // add the change output
    ret = wally_tx_add_elements_raw_output(tx, 
                                            scriptPubkey, scriptPubkey_len, 
                                            asset, WALLY_TX_ASSET_CT_ASSET_LEN,
                                            value, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN,
                                            NULL, 0, // nonce
                                            NULL, 0, // surjectionproof
                                            NULL, 0, // rangeproof
                                            0);
    if (ret != 0) {
        printf("wally_tx_add_elements_raw_output failed with %d error code\n", ret);
    }

cleanup:
    clearThenFree(scriptPubkey, scriptPubkey_len);

    return ret;
}

int addIssuanceInputToTx(struct wally_tx *tx, const unsigned char *prevTxID, const unsigned char *contractHash) {
    unsigned char value[WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN];
    int ret = 1;

    // get the unblinded confidential value from amount in satoshis
    if ((ret = wally_tx_confidential_value_from_satoshi(ISSUANCE_ASSET_AMT, value, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN)) != 0) {
        printf("wally_tx_confidential_value_from_satoshi failed with %d error code\n", ret);
        return ret;
    }

    // add the input including issuance to the transaction
    ret = wally_tx_add_elements_raw_input(tx,
                                            prevTxID, WALLY_TXHASH_LEN,
                                            (uint32_t)0 | WALLY_TX_ISSUANCE_FLAG,
                                            INPUT_DEACTIVATE_SEQUENCE, // sequence must be set at 0xffffffff if not used
                                            NULL, 0, // scriptSig and its length
                                            NULL, // witness stack
                                            NULL, 0, // issuance has an empty nonce
                                            contractHash, WALLY_TX_ASSET_TAG_LEN, // the contract hash provided in input, only reversed
                                            value, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN, // explicit (unblinded) value
                                            NULL, 0, // blinded token amount, this should be 0
                                            NULL, 0, // issuance rangeproof
                                            NULL, 0, // token rangeproof, since we don't have a token output we can just forget it for now
                                            NULL, // peginWitness, this should be NULL for non pegin transaction
                                            0); // flag, must be 0

    if (ret != 0) {
        fprintf(stderr, "wally_tx_add_elements_raw_input failed with %d error code\n", ret);
    }

    return ret;
}

int addInputToTx(struct wally_tx *tx, const unsigned char *prevTxID) {
    int ret = 1;

    // add the input to the transaction
    ret = wally_tx_add_elements_raw_input(tx,
                                            prevTxID, WALLY_TXHASH_LEN,
                                            (uint32_t)1,
                                            INPUT_DEACTIVATE_SEQUENCE, // sequence must be set at 0xffffffff if not used
                                            NULL, 0, // scriptSig and its length
                                            NULL, // witness stack
                                            NULL, 0, // issuance has an empty nonce
                                            NULL, 0, // the contract hash provided in input, only reversed
                                            NULL, 0, // explicit (unblinded) value
                                            NULL, 0, // blinded token amount, this should be 0
                                            NULL, 0, // issuance rangeproof
                                            NULL, 0, // token rangeproof, since we don't have a token output we can just forget it for now
                                            NULL, // peginWitness, this should be NULL for non pegin transaction
                                            0); // flag, must be 0

    if (ret != 0) {
        fprintf(stderr, "wally_tx_add_elements_raw_input failed with %d error code\n", ret);
    }

    return ret;
}
