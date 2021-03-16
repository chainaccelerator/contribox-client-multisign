# include "contribox.h"

int initializePRNG(const unsigned char *entropy, const size_t len) {
    int ret = 1;
    if ((ret = wally_secp_randomize(entropy, len)) != 0) {
        return ret;
    }
    
    srand((unsigned int)*entropy);

    return ret;
}
 
char *encryptStringWithPubkey(const char *pubkey_hex, const char *toEncrypt, unsigned char *ephemeralPrivkey) {
    unsigned char   *buffer = NULL;
    unsigned char   ephemeralPubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   key[SHA256_LEN];
    char            *encryptedFile = NULL;
    size_t          written;
    int             ret;

    // verify that provided entropy is a valid private key
    if ((ret = wally_ec_private_key_verify(ephemeralPrivkey, EC_PRIVATE_KEY_LEN))) {
        printf("wally_ec_private_key_verify failed with %d error code\n", ret);
        printf("Provided entropy can't be used as a private key, try again with another entropy\n");
        return NULL;
    }

    // get the public key
    if ((ret = wally_ec_public_key_from_private_key(ephemeralPrivkey, EC_PRIVATE_KEY_LEN, ephemeralPubkey, EC_PUBLIC_KEY_LEN))) {
        printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
        return NULL;
    }

    // convert the pubkey in bytes form
    if ((ret = wally_hex_to_bytes(pubkey_hex, pubkey, sizeof(pubkey), &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        return NULL;
    }

    if (written != EC_PUBLIC_KEY_LEN) {
        printf("Provided hex is not a valid public key, it's %zu long\n", written);
        return NULL;
    }

    // get the shared secret with ECDH
    if ((ret = wally_ecdh(pubkey, EC_PUBLIC_KEY_LEN, ephemeralPrivkey, EC_PRIVATE_KEY_LEN, key, sizeof(key)))) {
        printf("wally_ecdh failed with %d error code\n", ret);
        return NULL;
    }

    if ((buffer = encryptWithAes(toEncrypt, key, &written)) == NULL) {
        printf("encryptWithAes failed\n");
        return NULL;
    }

    // erase all private material from memory
    memset(key, '\0', sizeof(key));
    memset(ephemeralPrivkey, '\0', EC_PRIVATE_KEY_LEN);

    if ((ret = wally_base58_from_bytes(buffer, written, BASE58_FLAG_CHECKSUM, &encryptedFile)) != 0) {
        printf("wally_base58_from_bytes failed\n");
    };

    clearThenFree(buffer, written);

    return encryptedFile;
}

char    *decryptStringWithPrivkey(const char *encryptedString, const char *privkey_hex, const char *ephemeralPubkey_hex) {
    unsigned char   privkey[EC_PRIVATE_KEY_LEN];
    unsigned char   ephemeralPubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   key[PBKDF2_HMAC_SHA256_LEN];
    char            *clearMessage = NULL;
    int             ret = 1;
    size_t          written;

    // get privkey in bytes
    if ((ret = wally_hex_to_bytes(privkey_hex, privkey, sizeof(privkey), &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        return NULL;
    }

    // get pubkey in bytes
    if ((ret = wally_hex_to_bytes(ephemeralPubkey_hex, ephemeralPubkey, sizeof(ephemeralPubkey), &written)) != 0) {
        printf("wally_hex_to_bytes failed with %d error code\n", ret);
        return NULL;
    }

    // get the shared secret with ECDH
    if ((ret = wally_ecdh(ephemeralPubkey, sizeof(ephemeralPubkey), privkey, sizeof(privkey), key, sizeof(key)))) {
        printf("wally_ecdh failed with %d error code\n", ret);
        return NULL;
    }

    if (!(clearMessage = decryptWithAes(encryptedString, key))) {
        printf("decryptWithAes failed\n");
    }

    memset(key, '\0', sizeof(key));

    return clearMessage;
}

int main(int ac, char **av) {
    char            *command = NULL;
    char            *privkey_hex = NULL;
    char            *pubkey_hex = NULL;
    char            *ephemeralPubkey_hex = NULL;
    char            *message = NULL;
    char            *cipher = NULL;
    unsigned char   privkey[EC_PRIVATE_KEY_LEN];
    unsigned char   ephemeralPrivkey[EC_PRIVATE_KEY_LEN];
    unsigned char   ephemeralPubkey[EC_PUBLIC_KEY_LEN];
    unsigned char   entropy[SHA256_LEN];
    size_t          encrypt = 0; // if 0, we're decrypting, if 1, we're encrypting
    size_t          written;
    int             ret = 1;

    if (ac != 6) {
        fprintf(stderr, "Please provide a command (encrypt/decrypt) and the expected arguments (see README)\n");
        exit(1);
    }

    command = strndup(av[1], strlen(av[1]));

    if (!(strncmp(command, ENCRYPT_COMMAND, sizeof(ENCRYPT_COMMAND)))) {
        encrypt = 1;
    } 
    else if (!(strncmp(command, DECRYPT_COMMAND, sizeof(DECRYPT_COMMAND)))) {
        encrypt = 0;
    } else {
        fprintf(stderr, "command must be either %s or %s\n", ENCRYPT_COMMAND, DECRYPT_COMMAND);
        exit(1);
    }

    // initialize libwally
    if ((wally_init(0))) {
        fprintf(stderr, "libwally failed to initialize.\n");
        exit(1);
    }

    if ((ret = wally_hex_to_bytes(av[2], entropy, sizeof(entropy), &written)) != 0) {
        fprintf(stderr, "wally_hex_to_bytes failed with %d error code\n", ret);
        exit(1);
    }

    if (initializePRNG(entropy, sizeof(entropy))) {
        fprintf(stderr, "Failed to initialize PRNG\n");
        exit(1);
    }

    if ((encrypt == 1) && (ac == ENCRYPT_ARGUMENTS)) {
        // copy all arguments
        pubkey_hex = strndup(av[3], strlen(av[3]));
        message = strndup(av[4], strlen(av[4]));

        if ((ret = wally_hex_to_bytes(av[5], ephemeralPrivkey, sizeof(ephemeralPrivkey), &written)) != 0) {
            fprintf(stderr, "wally_hex_to_bytes failed with %d error code\n", ret);
            exit(1); 
        }

        // take the ephemeral pubkey
        if ((ret = wally_ec_public_key_from_private_key(ephemeralPrivkey, sizeof(ephemeralPrivkey), ephemeralPubkey, sizeof(ephemeralPubkey)))) {
            printf("wally_ec_public_key_from_private_key failed with %d error code\n", ret);
            exit(1);
        }

        // print the pubkey
        printBytesInHex(ephemeralPubkey, sizeof(ephemeralPubkey), "ephemeral public key");

        // TODO: sanity check on each argument

        // encrypt toEncrypt string
        cipher = encryptStringWithPubkey(pubkey_hex, message, ephemeralPrivkey);

        if (!cipher) {
            fprintf(stderr, "encryptStringWithPubkey failed\n");
            exit(1);
        } else {
            printf("encrypted message:\n%s\n", cipher);
        }

        return 0;
    } else if ((encrypt == 0) && (ac == DECRYPT_ARGUMENTS)) {
        ephemeralPubkey_hex = strndup(av[3], strlen(av[3]));
        cipher = strndup(av[4], strlen(av[4]));
        privkey_hex = strndup(av[5], strlen(av[5]));

        message = decryptStringWithPrivkey(cipher, privkey_hex, ephemeralPubkey_hex);

        if (!message) {
            fprintf(stderr, "decryptStringWithPrivkey failed\n");
            exit(1);
        } else {
            printf("clear message:\n%s\n", message);
        }

        return 0;
    }

    fprintf(stderr, "%s with command %s must take exactly %d arguments.\n", av[0], command, encrypt ? ENCRYPT_ARGUMENTS : DECRYPT_ARGUMENTS);
    return 1; 

}
