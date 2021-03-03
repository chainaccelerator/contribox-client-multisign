#include "contribox.h"

unsigned char   *getWitnessProgram(const unsigned char *script, const size_t script_len, int *isP2WSH) {
    unsigned char   *program = NULL;
    int             ret;
    size_t          written;

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

char    *getSegwitAddressFromScript(const unsigned char *script, const size_t script_len) {
    unsigned char   *program = NULL;
    char            *address = NULL;
    int             ret;
    int             isP2WSH;

    // get the program from the script
    if (!(program = getWitnessProgram(script, script_len, &isP2WSH))) {
        printf("getWitnessProgram failed\n");
        goto cleanup;
    }

    // create the unconfidential address from program
    if ((ret = wally_addr_segwit_from_bytes(program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN, 
                                            UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST, 
                                            0, 
                                            &address))) {
        printf("wally_addr_segwit_from_bytes failed with %d error code\n", ret);
    }

cleanup:
    clearThenFree(program, isP2WSH ? WALLY_SCRIPTPUBKEY_P2WSH_LEN : WALLY_SCRIPTPUBKEY_P2WPKH_LEN);

    return address;
}

char    *getP2pkhFromPubkey(const unsigned char *pubkey) {
    unsigned char   p2pkhScript[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    char            *address = NULL;
    size_t          written;
    int             ret = 1;

    // get the scriptpubkey
    if ((ret = wally_scriptpubkey_p2pkh_from_bytes(pubkey, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, p2pkhScript, sizeof(p2pkhScript), &written))) {
        printf("wally_scriptpubkey_p2pkh_from_bytes failed with %d error code\n", ret);
        return NULL;
    }

    // encode the scriptpubkey in a legacy address
    if ((ret = wally_scriptpubkey_to_address(p2pkhScript, sizeof(p2pkhScript), WALLY_NETWORK_LIQUID_REGTEST, &address))) {
        printf("wally_scriptpubkey_to_address failed with %d error code\n", ret);
        return NULL;
    }

    return address;
}
