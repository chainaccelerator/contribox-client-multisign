#include "contribox.h"

static int  signHashECDSA(const unsigned char *signingKey, const unsigned char *toSign, const uint32_t flags, unsigned char *signature, size_t *sig_len) {
    unsigned char   sig[EC_SIGNATURE_LEN];
    int             ret = 1;

    *sig_len = flags & EC_FLAG_RECOVERABLE ? EC_SIGNATURE_RECOVERABLE_LEN : EC_SIGNATURE_LEN;
    if ((ret = wally_ec_sig_from_bytes(signingKey, EC_PRIVATE_KEY_LEN,
                                        toSign, EC_MESSAGE_HASH_LEN, // the signed message must be a 32B (ie. sha256) hash
                                        flags,
                                        sig, *sig_len)) != 0) {
        printf("wally_ec_sig_from_bytes failed with %d error code\n", ret);
        return ret;
    }

    printBytesInHex(sig, *sig_len, "sig");
    printf("sig_len is %zu\n", *sig_len);

    if (!(flags & EC_FLAG_RECOVERABLE)) {
        // convert the signature to DER only if we're signing a transaction (non recoverable signature)
        printf("encoding signature to hex\n");
        if ((ret = wally_ec_sig_to_der(sig, EC_SIGNATURE_LEN, signature, EC_SIGNATURE_DER_MAX_LEN, sig_len)) != 0) {
            printf("wally_ec_sig_to_der failed with %d error code\n", ret);
            return ret;
        }

    } else {
        memcpy(signature, sig, *sig_len);
    }

    printBytesInHex(signature, *sig_len, "signature");
    return ret;
}

int signMessageECDSA(const unsigned char *signingKey, const unsigned char *toSign, unsigned char *derSig, size_t *written) {
    uint32_t flags = EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE | EC_FLAG_GRIND_R;

    return signHashECDSA(signingKey, toSign, flags, derSig, written);
}

int verifyMessageECDSA(const unsigned char *pubkey, const unsigned char *hash, const unsigned char *sig) {
    int ret = 1;

    if ((ret = wally_ec_sig_verify(pubkey, EC_PUBLIC_KEY_LEN, hash, EC_MESSAGE_HASH_LEN, EC_FLAG_ECDSA, sig, EC_SIGNATURE_LEN))) {
        printf("wally_ec_sig_verify failed with %d error code\n", ret);
    }

    return ret;
}

int signTransactionECDSA(const unsigned char *signingKey, const unsigned char *toSign, unsigned char *derSig, size_t *written) {
    uint32_t flags = EC_FLAG_ECDSA | EC_FLAG_GRIND_R;

    return signHashECDSA(signingKey, toSign, flags, derSig, written);
}
