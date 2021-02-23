#include "contribox.h"

int signHashECDSA(const unsigned char *signingKey, const unsigned char *toSign, unsigned char *derSig, size_t *written) {
    unsigned char   sig[EC_SIGNATURE_LEN];
    int             ret = 1;

    if ((ret = wally_ec_sig_from_bytes(signingKey, EC_PRIVATE_KEY_LEN,
                                        toSign, EC_MESSAGE_HASH_LEN, // the signed message must be a 32B (ie. sha256) hash
                                        EC_FLAG_ECDSA | EC_FLAG_GRIND_R, // we optimize the signature (low r)
                                        sig, EC_SIGNATURE_LEN)) != 0) {
        printf("wally_ec_sig_from_bytes failed with %d error code\n", ret);
        return ret;
    }

    // convert the signature to DER
    if ((ret = wally_ec_sig_to_der(sig, EC_SIGNATURE_LEN, derSig, EC_SIGNATURE_DER_MAX_LEN, written)) != 0) {
        printf("wally_ec_sig_to_der failed with %d error code\n", ret);
        return ret;
    }

    return ret;
}