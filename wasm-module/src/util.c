#include "contribox.h"

void    clearThenFree(void *p, size_t len) {
    if (p) {
        memset(p, '\0', len);
        free(p);
        p = NULL;
    }
}

void    freeTxInfo(struct txInfo **initialInput) {
    struct txInfo *temp;
    struct txInfo *to_clear;

    if (!initialInput || !*initialInput) {
        return;
    }

    to_clear = *initialInput;
    while (to_clear) {
        clearThenFree(to_clear->assetBlindingFactor, BLINDING_FACTOR_LEN);
        clearThenFree(to_clear->valueBlindingFactor, BLINDING_FACTOR_LEN);
        clearThenFree(to_clear->scriptPubkey, to_clear->scriptPubkey_len);
        clearThenFree(to_clear->address, strlen(to_clear->address));

        temp = to_clear;

        // get the next struct address 
        to_clear = to_clear->next;

        clearThenFree(temp, sizeof(*temp));
    }
}

struct txInfo *initTxInfo() {
    struct txInfo *res;

    if (!(res = calloc(1, sizeof(*res)))) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    // if ((!(res->clearAsset = calloc(ASSET_TAG_LEN, sizeof(unsigned char)))) || 
    //     ((!(res->assetBlindingFactor = calloc(BLINDING_FACTOR_LEN, sizeof(unsigned char)))) ||
    //     ((!(res->valueBlindingFactor = calloc(BLINDING_FACTOR_LEN, sizeof(unsigned char))))))) {
    //         printf(MEMORY_ERROR);
    //         freeTxInfo(&res);
    //         return NULL;
    //     }
    if ((!(res->assetBlindingFactor = calloc(BLINDING_FACTOR_LEN, sizeof(unsigned char)))) ||
        ((!(res->valueBlindingFactor = calloc(BLINDING_FACTOR_LEN, sizeof(unsigned char)))))) {
            printf(MEMORY_ERROR);
            freeTxInfo(&res);
            return NULL;
        }

    // other members have been set to 0 by the calloc function, and will be initialized if necessary

    return res;
}

void    getRandomBytes(unsigned char *array, const size_t array_len) {
    int divisor = RAND_MAX / (UCHAR_MAX+1);
    int temp;
    int retval;

    for (int i = 0; i < array_len; i++) {
        retval = rand();
        do {
            temp = retval;
            retval = temp / divisor;
        }   while (retval > UCHAR_MAX);
        array[i] = (unsigned char)retval;
    }
}

void    *reverseBytes(const unsigned char *bytes, const size_t bytes_len) {
    unsigned char *bytes_out = NULL;

    if (!(bytes_out = calloc(bytes_len, sizeof(*bytes_out)))) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        *(bytes_out + bytes_len - i - 1) = *(bytes + i);
    }

    return bytes_out;
}

unsigned char *convertHexToBytes(const char *hexstring, size_t *bytes_len) {
    /* takes a hexstring, allocates and returns a bytes array */
    unsigned char *bytes;
    int ret;
    size_t written;

    *bytes_len = strlen(hexstring) / 2;
    if (!(bytes = malloc(*bytes_len))) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    if ((ret = wally_hex_to_bytes(hexstring, bytes, *bytes_len, &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        free(bytes);
        return NULL;
    }

    return bytes;
}

unsigned char *reversedBytesFromHex(const char *hexString, size_t *bytes_len) {
    unsigned char *bytes = NULL;
    unsigned char *reversedBytes = NULL;

    // get the bytes from the hex string
    if (!(bytes = convertHexToBytes(hexString, bytes_len))) {
        printf("convertHexToBytes failed\n");
        return NULL;
    }

    // reverse the hash bytes sequence
    if (!(reversedBytes = reverseBytes(bytes, *bytes_len))) {
        printf("reverseBytes failed\n");
        clearThenFree(bytes, *bytes_len);
        return NULL;
    }

    clearThenFree(bytes, *bytes_len);

    return reversedBytes;
}

void    printBytesInHex(const unsigned char *toPrint, const size_t len, const char *label) {
    char *toPrint_hex;
    int ret;

    if ((ret = wally_hex_from_bytes(toPrint, len, &toPrint_hex)) != 0) {
        printf("wally_hex_from_bytes failed with %d error code\n", ret);
        return;
    }

    printf("%s is %s\n", label, toPrint_hex);
    clearThenFree(toPrint_hex, len * 2);
}

void    printBytesInHexReversed(const unsigned char *toPrint, const size_t len, const char *label) {
    unsigned char *reversed;

    if (!(reversed = reverseBytes(toPrint, len))) {
        printf("reversed failed\n");
        return;
    }

    printBytesInHex(reversed, len, label);

    clearThenFree(reversed, len);
}

unsigned char   *getWitnessProgram(const unsigned char *script, const size_t script_len, int *isP2WSH) {
    unsigned char *program = NULL;
    int ret;
    size_t written;

    // test the script to see if it is a valid pubkey
    if (wally_ec_public_key_verify(script, script_len)) { // return != 0 means the script is not a valid pubkey
        if (!(program = malloc(WALLY_SCRIPTPUBKEY_P2WSH_LEN))) {
            printf(MEMORY_ERROR);
            return NULL;
        }

        // we generate a P2WSH from the script
        if ((ret = wally_witness_program_from_bytes(script, 
                                                    script_len, 
                                                    WALLY_SCRIPT_SHA256, // we hash the script with SHA256 to generate the P2WSH program 
                                                    program, 
                                                    WALLY_SCRIPTPUBKEY_P2WSH_LEN, 
                                                    &written)) != 0) {
            printf("wally_witness_program_from_bytes failed to generate P2WSH with %d error code\n", ret);
            clearThenFree(program, WALLY_SCRIPTPUBKEY_P2WSH_LEN);
            return NULL;
        }

        // we set isP2WSH to 1
        *isP2WSH = 1;
    }
    else {
        if (!(program = malloc(WALLY_SCRIPTPUBKEY_P2WPKH_LEN))) {
            printf(MEMORY_ERROR);
            return NULL;
        }

        // the script is actually a pubkey, we generate a P2WPKH
        if ((ret = wally_witness_program_from_bytes(script, 
                                                    script_len, 
                                                    WALLY_SCRIPT_HASH160, // we hash the script with RIPEMD160 to generate the P2WPKH program 
                                                    program, 
                                                    WALLY_SCRIPTPUBKEY_P2WPKH_LEN, 
                                                    &written)) != 0) {
            printf("wally_witness_program_from_bytes failed to generate P2PKH with %d error code\n", ret);
            clearThenFree(program, WALLY_SCRIPTPUBKEY_P2WPKH_LEN);
            return NULL;
        }

        *isP2WSH = 0;
    }

    return program;
}
