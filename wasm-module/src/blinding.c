# include "contribox.h"

int analyzeCAddress(const char *CAddress, char *address, unsigned char blindingPubkey[EC_PUBLIC_KEY_LEN], unsigned char *scriptPubkey, size_t scriptPubkey_len) {
    int ret = 1;
    size_t written;

    // get the unconfidential address
    ret = wally_confidential_addr_to_addr_segwit(CAddress, CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, &address);
    if (ret != 0) {
        printf("wally_confidential_addr_to_addr_segwit failed with %d error code\n", ret);
        goto cleanup;
    }

    // get the blindingPubkey in the assetCaddress
    ret = wally_confidential_addr_segwit_to_ec_public_key(CAddress, CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, blindingPubkey, EC_PUBLIC_KEY_LEN);
    if (ret != 0) {
        printf("wally_confidential_addr_to_ec_public_key failed with %d error code\n", ret);
        goto cleanup;
    }

    // get the script pubkey corresponding to the destination address
    ret = wally_addr_segwit_to_bytes(address, UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 0, scriptPubkey, scriptPubkey_len, &written);
    if (ret != 0) {
        printf("wally_addr_segwit_to_bytes failed with %d error code\n", ret);
        goto cleanup;
    } 


cleanup:
    clearThenFree(address, strlen(address));
    return ret;
}

struct blindingInfo *unblindTxOutput(const struct wally_tx_output *output, const unsigned char *masterBlindingKey) {
    struct blindingInfo *unblindedOutput = NULL;
    unsigned char privateBlindingKey[EC_PRIVATE_KEY_LEN];
    int ret = 1;

    if (!(unblindedOutput = initBlindingInfo())) {
        printf("Failed to initialize blindingInfo struct\n");
        return NULL; 
    }

    // we compute the blinding key for the script
    if ((output->script[0] == OP_0) && (output->script_len == WALLY_SCRIPTPUBKEY_P2WPKH_LEN)) {
        if ((ret = wally_asset_blinding_key_to_ec_private_key(masterBlindingKey, HMAC_SHA512_LEN, output->script, WALLY_SCRIPTPUBKEY_P2WPKH_LEN, privateBlindingKey, EC_PRIVATE_KEY_LEN)) != 0) {
            printf("wally_asset_blinding_key_to_ec_private_key failed with %d error code\n", ret);
            return NULL;
        }
    }
    // this case should not occur for now, as we will have explicit blinding key for multisig outputs
    else if ((output->script[0] == OP_0) && (output->script_len == WALLY_SCRIPTPUBKEY_P2WSH_LEN)) {
        if ((ret = wally_asset_blinding_key_to_ec_private_key(masterBlindingKey, HMAC_SHA512_LEN, output->script, WALLY_SCRIPTPUBKEY_P2WSH_LEN, privateBlindingKey, EC_PRIVATE_KEY_LEN)) != 0) {
            printf("wally_asset_blinding_key_to_ec_private_key failed with %d error code\n", ret);
            return NULL; 
        }
    }
    else {
        printf("Invalid Segwit version or invalid program length for 0 version\n"); // this could happen with fee outputs or taproot script
        return NULL;
    }

    // try asset unblind with all those data
    if ((ret = wally_asset_unblind(output->nonce,
                                    EC_PUBLIC_KEY_LEN,
                                    privateBlindingKey,
                                    EC_PRIVATE_KEY_LEN,
                                    output->rangeproof,
                                    output->rangeproof_len,
                                    output->value,
                                    output->value_len,
                                    output->script,
                                    output->script_len,
                                    output->asset,
                                    ASSET_GENERATOR_LEN,
                                    unblindedOutput->clearAsset,
                                    ASSET_TAG_LEN, 
                                    unblindedOutput->assetBlindingFactor,
                                    BLINDING_FACTOR_LEN,
                                    unblindedOutput->valueBlindingFactor,
                                    BLINDING_FACTOR_LEN,
                                    &(unblindedOutput->clearValue))) != 0) {
        printf("wally_asset_unblind failed with %d error code\n", ret);
        return NULL;
    }

    return unblindedOutput; 
}

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

unsigned long long *getValuesList(const struct blindingInfo *initialInput, size_t *values_len, size_t *num_inputs) {
    const struct blindingInfo *temp;
    unsigned long long *values = NULL;

    temp = initialInput;
    *values_len = 0;
    *num_inputs = 0;
    while (temp) {
        (*values_len)++;
        if (temp->isInput == 1) 
            (*num_inputs)++;
        temp = temp->next;
    }

    // allocate memory for the values list
    values = calloc(*values_len, sizeof(*values));
    if (!values) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    // copy the values to the list
    temp = initialInput;
    for (size_t i = 0; i < *values_len; i++) {
        values[i] = (unsigned long long)temp->clearValue;
        temp = temp->next;
    }

    return values;
}

unsigned char *getAbfArray(const struct blindingInfo *initialInput, const size_t values_len) {
    const struct blindingInfo *temp;
    unsigned char *abf = NULL;

    // allocate abf array
    abf = calloc(values_len * BLINDING_FACTOR_LEN, sizeof(*abf)); // size must be a multiple of BLINDING_FACTOR_LEN
    if (!abf) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    temp = initialInput;
    for (size_t i = 0; i < values_len; i++) {
        memcpy(abf + (BLINDING_FACTOR_LEN * i), temp->assetBlindingFactor, BLINDING_FACTOR_LEN);
        temp = temp->next;
    }

    return abf;
}

unsigned char *getVbfArray(const struct blindingInfo *initialInput, const size_t values_len) {
    const struct blindingInfo *temp;
    unsigned char *vbf = NULL;

    // allocate vbf array
    vbf = calloc((values_len - 1) * BLINDING_FACTOR_LEN, sizeof(*vbf)); // size must be a multiple of BLINDING_FACTOR_LEN
    if (!vbf) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    temp = initialInput;
    for (size_t i = 0; i < values_len - 1; i++) {
        memcpy(vbf + (BLINDING_FACTOR_LEN * i), temp->valueBlindingFactor, BLINDING_FACTOR_LEN);
        temp = temp->next;
    }

    return vbf;
}

int getLastVbf(const struct blindingInfo *initialInput, unsigned char *lastVbf) {
    size_t values_len = 0;
    size_t num_inputs = 0;
    unsigned long long *values = NULL;
    unsigned char *abf = NULL;
    unsigned char *vbf = NULL;
    int ret = 1;

    values = getValuesList(initialInput, &values_len, &num_inputs);
    if (!values || values_len == 0) {
        printf("Failed to get values array\n");
        return ret;
    } 

    abf = getAbfArray(initialInput, values_len);
    vbf = getVbfArray(initialInput, values_len);
    if (!abf || !vbf) {
        printf("Failed to get abf or vbf array\n");
        return ret;
    }

    ret = wally_asset_final_vbf(values, // array containing all the clear values
                                values_len, // inputs + outputs
                                num_inputs, // num_outputs is implicit
                                abf, // array containing values_len abf
                                values_len * BLINDING_FACTOR_LEN,
                                vbf, // array containing values_len - 1 vbf
                                (values_len - 1) * BLINDING_FACTOR_LEN,
                                lastVbf,
                                BLINDING_FACTOR_LEN);

cleanup:
    clearThenFree(values, values_len * sizeof(*values));
    clearThenFree(abf, values_len * BLINDING_FACTOR_LEN); 
    clearThenFree(vbf, (values_len - 1) * BLINDING_FACTOR_LEN);

    return ret;
}

void    addBlindingInfoToList(struct blindingInfo *firstInput, struct blindingInfo *new) {
	struct blindingInfo	*temp;

    temp = firstInput;
    
    while (temp && temp->next)
        temp = temp->next;
    temp->next = new;
}

int generateAssetGenerator(struct blindingInfo *element) {
    int ret;

    ret = wally_asset_generator_from_bytes(element->clearAsset, ASSET_TAG_LEN, element->assetBlindingFactor, BLINDING_FACTOR_LEN, element->generator, ASSET_GENERATOR_LEN);
    if (ret != 0) {
        printf("wally_asset_generator_from_bytes failed with %d error code\n", ret);
    }

    return ret;
}

int generateValueCommitment(struct blindingInfo *element) {
    int ret;

    ret = wally_asset_value_commitment(element->clearValue,
                                        element->valueBlindingFactor, BLINDING_FACTOR_LEN,
                                        element->generator, ASSET_GENERATOR_LEN,
                                        element->valueCommitment, ASSET_COMMITMENT_LEN);
    if (ret != 0) {
        printf("wally_asset_value_commitment failed with %d error code\n", ret);
    }

    return ret;
}

int blindOutputs(struct blindingInfo *initialInput) {
    struct blindingInfo *temp;
    unsigned char ephemeralPrivkey[EC_PRIVATE_KEY_LEN];
    unsigned char surjectionproofRandomBytes[32];
    unsigned char *inputAssets;
    unsigned char *inputAbfs;
    unsigned char *inputGenerators;
    size_t num_inputs = 0;
    int ret = 1;
    size_t written;

    temp = initialInput;
    // count the number of inputs. We assume that all the inputs are at the beginning of the list
    while (temp->isInput) {
        num_inputs++;
        temp = temp->next;
    }

    // allocate memory for input assets, abfs and generators (we need them in an array for surjection proof computation)
    if (!(inputAssets = calloc(num_inputs * ASSET_TAG_LEN, sizeof(*inputAssets))) || 
            !(inputAbfs = calloc(num_inputs * BLINDING_FACTOR_LEN, sizeof(*inputAbfs))) || 
            !(inputGenerators = calloc(num_inputs * ASSET_GENERATOR_LEN, sizeof(*inputGenerators)))) {
        printf(MEMORY_ERROR);
        return ret;
    }


    temp = initialInput; // we rewind back to the first input to copy clear assets, abfs and generators for each inputs
    for (size_t i = 0; i < num_inputs; i++) {
        memcpy(inputAssets + (i * ASSET_TAG_LEN), temp->clearAsset, ASSET_TAG_LEN);
        memcpy(inputAbfs + (i * BLINDING_FACTOR_LEN), temp->assetBlindingFactor, BLINDING_FACTOR_LEN);
        memcpy(inputGenerators + (i * ASSET_GENERATOR_LEN), temp->generator, ASSET_GENERATOR_LEN);
        temp = temp->next;
    }
    printBytesInHex(inputAssets, ASSET_TAG_LEN * num_inputs, "inputAssets");
    printBytesInHex(inputAbfs, BLINDING_FACTOR_LEN * num_inputs, "inputAbfs");
    printBytesInHex(inputGenerators, ASSET_GENERATOR_LEN * num_inputs, "inputGenerators");

    // we now loop through each remaining outputs to set the proofs
    while (temp) {
        // get random bytes for the surjectionproof
        getRandomBytes(surjectionproofRandomBytes, sizeof(surjectionproofRandomBytes));

        // get surjection proof size
        if ((ret = wally_asset_surjectionproof_size(num_inputs, &(temp->surjectionproof_len))) != 0) {
            printf("wally_asset_surjectionproof_size failed with %d error code\n", ret);
            return ret;
        }

        // allocate the surjectionproof array
        if (!(temp->surjectionproof = calloc(temp->surjectionproof_len, sizeof(*(temp->surjectionproof))))) {
            printf(MEMORY_ERROR);
            return 1;
        }

        // get surjection proof
        ret = wally_asset_surjectionproof(temp->clearAsset, ASSET_TAG_LEN,
                                    temp->assetBlindingFactor, BLINDING_FACTOR_LEN,
                                    temp->generator, ASSET_GENERATOR_LEN,
                                    surjectionproofRandomBytes, 32,
                                    inputAssets, ASSET_TAG_LEN * num_inputs,
                                    inputAbfs, BLINDING_FACTOR_LEN * num_inputs,
                                    inputGenerators, ASSET_GENERATOR_LEN * num_inputs,
                                    temp->surjectionproof, temp->surjectionproof_len,
                                    &written);
        if (ret != 0) {
            printf("wally_asset_surjectionproof failed with %d error code\n", ret);
            return ret;
        }

        // generate a random ephemeral private key for rangeproof generation
        getRandomBytes(ephemeralPrivkey, EC_PRIVATE_KEY_LEN);

        // derive the corresponding ephemeral pubkey and save it as a nonce
        ret = wally_ec_public_key_from_private_key(ephemeralPrivkey, EC_PRIVATE_KEY_LEN, temp->nonce, EC_PUBLIC_KEY_LEN);
        if (ret != 0) {
            printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
            return ret;
        }

        // generate rangeproof for this output
        ret = wally_asset_rangeproof(temp->clearValue,
                                        temp->blindingPubkey, EC_PUBLIC_KEY_LEN,
                                        ephemeralPrivkey, EC_PRIVATE_KEY_LEN,
                                        temp->clearAsset, ASSET_TAG_LEN,
                                        temp->assetBlindingFactor, BLINDING_FACTOR_LEN,
                                        temp->valueBlindingFactor, BLINDING_FACTOR_LEN,
                                        temp->valueCommitment, ASSET_COMMITMENT_LEN,
                                        temp->scriptPubkey, temp->scriptPubkey_len,
                                        temp->generator, ASSET_GENERATOR_LEN,
                                        (uint64_t)1, // recommended min value
                                        0, // recommended value for exponent
                                        52, // recommended value for min_bits
                                        temp->rangeproof, ASSET_RANGEPROOF_MAX_LEN, &written);
        if (ret != 0) {
            printf("wally_asset_rangeproof failed with %d error code\n", ret);
            return ret;
        }
        temp->rangeproof_len = written;
        temp = temp->next;
    }

cleanup:
    clearThenFree(inputAssets, num_inputs * ASSET_TAG_LEN); 
    clearThenFree(inputAbfs, num_inputs * BLINDING_FACTOR_LEN); 
    clearThenFree(inputGenerators, ASSET_GENERATOR_LEN);

    return ret;
}


int populateBlindingInfoForProposalTx(struct blindingInfo *initialInput, const unsigned char *newAssetID, const char *assetCAddress, const char *changeCAddress) {
    /* We will build a linked list that starts with the UTXO we spend and add:
    * - an issuance input (wich is not really an input but can be considered one for blinding purpose)
    * - an output we will send the newly created asset to
    * - an output we will send the asset in the spent UTXO
    * For each of these we need to set a few flags (isInput and isNewAsset)
    * and to fill in some data:
    * - asset ID (either the one we have in the provided UTXO or the one we just created)
    * - a value in sat (will be `1` most of the time I think)
    * - an asset blinding factor and a value blinding factor (randomly generated, except the last value blinding factor)
    * - an asset generator (computed with a dedicated function in libwally)
    * For the outputs ONLY we also need to decompose the provided confidential addresses:
    * - a blinding pubkey (contained in the address)
    * - the scriptpubkey
    * - the unconfidential address */
    int ret = 1;
    struct blindingInfo *temp;
    unsigned char *lastVbf;

    // initiate the issuance input
    if (!(temp = initBlindingInfo())) {
        printf("Failed to initialize blindingInfo struct\n");
        goto cleanup;
    }

    // now add the new asset ID
    memcpy(temp->clearAsset, newAssetID, SHA256_LEN);
    // set isNewAsset isInput to 1 and clearValue
    temp->isNewAsset = 1;
    temp->isInput = 1;
    temp->clearValue = ISSUANCE_ASSET_AMT;

    // we generate random blinding factors for the issuance, since we can't take it from an UTXO like we did with the "real" input
    getRandomBytes(temp->assetBlindingFactor, BLINDING_FACTOR_LEN);
    getRandomBytes(temp->valueBlindingFactor, BLINDING_FACTOR_LEN);

    // create asset generator
    if (generateAssetGenerator(temp)) {
        printf("generateAssetGenerator failed for issuance input\n");
        goto cleanup;
    }

    // create value commitment
    if ((ret = generateValueCommitment(temp)) != 0) {
        printf("generateAssetGenerators failed\n");
        goto cleanup;
    }

    // add the issuance input to our list
    addBlindingInfoToList(initialInput, temp);

    // now the same with the newAsset output
    if (!(temp = initBlindingInfo())) {
        printf("Failed to initialize blindingInfo struct\n");
        goto cleanup;
    }
    // now set isNewAsset and other relevant data
    memcpy(temp->clearAsset, newAssetID, SHA256_LEN);
    temp->isNewAsset = 1;
    temp->clearValue = ISSUANCE_ASSET_AMT;
    temp->scriptPubkey_len = WALLY_SCRIPTPUBKEY_P2WSH_LEN; // we assume that the destination for the new asset is a multisig
    // allocate the script pubkey
    if (!(temp->scriptPubkey = calloc(temp->scriptPubkey_len, sizeof(*(temp->scriptPubkey))))) {
        printf(MEMORY_ERROR);
        goto cleanup;
    }

    // analyze the confidential address
    ret = analyzeCAddress(assetCAddress, temp->address, temp->blindingPubkey, temp->scriptPubkey, temp->scriptPubkey_len);
    if (ret != 0) {
        printf("analyzeCAddress for new asset output failed\n");
        goto cleanup;
    }

    // we generate random blinding factors for the output
    getRandomBytes(temp->assetBlindingFactor, BLINDING_FACTOR_LEN);
    getRandomBytes(temp->valueBlindingFactor, BLINDING_FACTOR_LEN);

    // asset generator
    if (generateAssetGenerator(temp)) {
        printf("generateAssetGenerator failed for issuance input\n");
        goto cleanup;
    }

    // create value commitment
    if ((ret = generateValueCommitment(temp)) != 0) {
        printf("generateAssetGenerators failed\n");
        goto cleanup;
    }

    // add the new asset output to our list
    addBlindingInfoToList(initialInput, temp);

    // same with the change output, which is simply the asset spent by the proposer
    if (!(temp = initBlindingInfo())) {
        printf("Failed to initialize blindingInfo struct\n");
        goto cleanup;
    }
    // clearValue clearAsset must be the same than our initialInput
    memcpy(temp->clearAsset, initialInput->clearAsset, SHA256_LEN);
    temp->clearValue = initialInput->clearValue;
    temp->scriptPubkey_len = WALLY_SCRIPTPUBKEY_P2WPKH_LEN; // we assume that the destination for the change is another single sig controlled by the proposer
    // allocate the script pubkey
    if (!(temp->scriptPubkey = calloc(temp->scriptPubkey_len, sizeof(*(temp->scriptPubkey))))) {
        printf(MEMORY_ERROR);
        goto cleanup;
    }

    // analyze the confidential address
    ret = analyzeCAddress(changeCAddress, temp->address, temp->blindingPubkey, temp->scriptPubkey, temp->scriptPubkey_len);
    if (ret != 0) {
        printf("analyzeCAddress for change output failed\n");
        goto cleanup;
    }

    // we generate randomly asset blinding factor only for the last output
    getRandomBytes(temp->assetBlindingFactor, BLINDING_FACTOR_LEN);
    // we keep the pointer to vbf for this last output in a pointer for final vbf computation
    lastVbf = temp->valueBlindingFactor;

    // asset generator
    if (generateAssetGenerator(temp)) {
        printf("generateAssetGenerator failed for issuance input\n");
        goto cleanup;
    }

    // add the change output to our list
    addBlindingInfoToList(initialInput, temp);
 
    // compute the value blinding factor for the last output
    ret = getLastVbf(initialInput, lastVbf);
    if (ret != 0) {
        printf("getLastVbf failed\n");
        goto cleanup;
    }

    // create value commitment for the last output (don't forget to compute the last vbf before doing this)
    if ((ret = generateValueCommitment(temp)) != 0) {
        printf("generateAssetGenerators failed\n");
        goto cleanup;
    }

    if ((ret = blindOutputs(initialInput)) != 0) {
        printf("generateRangeproofs failed\n");
    }

cleanup:
    return ret;
}

int addBlindedOutputs(struct wally_tx *newTx, struct blindingInfo *initialInput) {
    /* Loop through all the blindingInfo we have for outputs and create and add outputs to a transaction */
    int ret = 1;
    struct blindingInfo *temp;
    char *test_hex;

    // loop up to the first output
    temp = initialInput;
    while (temp->isInput) {
        temp = temp->next;
    }

    // loop through all the rest and add an output to the transaction
    while (temp) {
        printBytesInHex(temp->surjectionproof, temp->surjectionproof_len, "surjectionproof");
        ret = wally_tx_add_elements_raw_output(newTx,
                                                temp->scriptPubkey, temp->scriptPubkey_len,
                                                temp->generator, WALLY_TX_ASSET_CT_ASSET_LEN, // this says `asset`, but it seems it's actually the generator
                                                temp->valueCommitment, WALLY_TX_ASSET_CT_VALUE_LEN,
                                                temp->nonce, WALLY_TX_ASSET_CT_NONCE_LEN, // this is the ephemeral pubkey, or nonce
                                                temp->surjectionproof, temp->surjectionproof_len, 
                                                temp->rangeproof, temp->rangeproof_len, // to be computed with wally_asset_rangeproof, not the same than the one of the input
                                                0);
        if (ret != 0) {
            printf("wally_tx_add_elements_raw_output failed with %d error code\n", ret);
            return ret;
        }
        temp = temp->next;
    }

    return ret;
}

int getIssuanceNonce(const unsigned char *prevTxID, const uint32_t *index, const unsigned char *masterBlindingKey, unsigned char *nonce) {
    /* Inspired from what is done in Elements, we create an OP_RETURN + prevout script and derive a key from it
    * using the master blinding key. This way we have a determinist nonce and garantee that it won't be reused
    */
    int ret = 1;
    size_t written;
    unsigned char index_array[sizeof(*index)];
    unsigned char message[SHA256_LEN + sizeof(*index)]; // we add up the txid (which is a sha256 hash) and the index (unsigned int)
    unsigned char script[sizeof(message) + 2]; // we add one byte for the OP_RETURN and one for the varint

    for (size_t i = 0; i < sizeof(*index); i++) {
        index_array[i] = (unsigned char)*index + i;
    }

    memcpy(message, prevTxID, SHA256_LEN);
    memcpy(message + SHA256_LEN, index_array, sizeof(index_array));

    if ((ret = wally_scriptpubkey_op_return_from_bytes(message, sizeof(message), 0, script, sizeof(script), &written)) != 0) {
        printf("wally_scriptpubkey_op_return_from_bytes failed with %d error code\n", ret);
        return ret;
    }

    if ((ret = wally_asset_blinding_key_to_ec_private_key(masterBlindingKey, HMAC_SHA512_LEN, script, written, nonce, EC_PRIVATE_KEY_LEN)) != 0) {
        printf("wally_asset_blinding_key_to_ec_private_key failed with %d error code\n", ret);
        return ret;
    }

    return ret;
}

int addIssuanceInput(struct wally_tx *newTx, struct blindingInfo *initialInput, const unsigned char *prevTxID, const unsigned char *contractHash, const unsigned char *masterBlindingKey) {
    /* complete the provided issuance input and add it to newTx */
    struct blindingInfo *issuance;
    uint32_t vout;
    unsigned char emptyNonce[WALLY_TX_ASSET_TAG_LEN] = { 0 };
    unsigned char nonce[EC_PRIVATE_KEY_LEN];
    int ret = 1;
    size_t written;

    // get the vout
    vout = (uint32_t)initialInput->vout;

    // set temp to the issuance input 
    issuance = initialInput->next;

    if (!issuance->isInput || !issuance->isNewAsset) {
        printf("selected blinding infos are not the issuance\n");
        return ret;
    }

    // if ((ret = getIssuanceNonce(prevTxID, &vout, masterBlindingKey, nonce)) != 0) {
    //     printf("getIssuanceNonce failed\n");
    //     return ret;
    // }

    // generate rangeproof for the issuance input
    ret = wally_asset_rangeproof_with_nonce(issuance->clearValue,
                                    emptyNonce, EC_PRIVATE_KEY_LEN, // nonce we compute with getIssuanceNonce()
                                    issuance->clearAsset, ASSET_TAG_LEN,
                                    issuance->assetBlindingFactor, BLINDING_FACTOR_LEN,
                                    issuance->valueBlindingFactor, BLINDING_FACTOR_LEN,
                                    issuance->valueCommitment, ASSET_COMMITMENT_LEN,
                                    NULL, 0,
                                    issuance->generator, ASSET_GENERATOR_LEN,
                                    (uint64_t)1, // recommended min value
                                    0, // recommended value for exponent
                                    52, // recommended value for min_bits
                                    issuance->rangeproof, ASSET_RANGEPROOF_MAX_LEN, &written);
    if (ret != 0) {
        printf("wally_asset_rangeproof failed with %d error code\n", ret);
        return ret;
    }
    issuance->rangeproof_len = written;

    // add the input to the transaction
    ret = wally_tx_add_elements_raw_input(newTx,
                                            prevTxID, WALLY_TXHASH_LEN,
                                            vout,
                                            INPUT_DEACTIVATE_SEQUENCE, // sequence must be set at 0xffffffff if not used
                                            NULL, 0, // scriptSig and its length
                                            NULL, // witness stack
                                            emptyNonce, WALLY_TX_ASSET_TAG_LEN, // nonce is ecdh(pubkey, privkey). For issuance there's no output to get the pubkey from
                                            // nonce, WALLY_TX_ASSET_TAG_LEN, // nonce is ecdh(pubkey, privkey). For issuance there's no output to get the pubkey from
                                            contractHash, WALLY_TX_ASSET_TAG_LEN, // the contract hash provided in input, only reversed
                                            issuance->valueCommitment, ASSET_COMMITMENT_LEN, // blinded issuance amount obtained with wally_asset_value_commitment()
                                            NULL, 0, // blinded token amount, this should be 0
                                            issuance->rangeproof, issuance->rangeproof_len, // issuance rangeproof
                                            NULL, 0, // token rangeproof, since we don't have a token output we can just forget it for now
                                            NULL, // peginWitness, this should be NULL for non pegin transaction
                                            0); // flag, must be 0

    if (ret != 0) {
        printf("wally_tx_add_elements_raw_input failed with %d error code\n", ret);
        return ret;
    }

    return ret;
}
