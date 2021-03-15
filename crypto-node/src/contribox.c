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

int main(int ac, char **av) {
    char            *command = NULL;
    char            *pubkey_hex = NULL;
    char            *toEncrypt = NULL;
    char            *cipher = NULL;
    unsigned char   ephemeralPrivkey[EC_PRIVATE_KEY_LEN];
    unsigned char   entropy[EC_PRIVATE_KEY_LEN];
    size_t          encrypt = 0; // if 0, we're decrypting, if 1, we're encrypting
    size_t          written;
    int             ret = 1;

    // check what is the command 
    command = strndup(av[1], strlen(av[1]));

    if (!command) {
        fprintf(stderr, "No command given.\n");
        exit(1);
    }

    if (!(strncmp(command, ENCRYPT_COMMAND, sizeof(ENCRYPT_COMMAND)))) {
        encrypt = 1;
    } 
    else if (!(strncmp(command, DECRYPT_COMMAND, sizeof(DECRYPT_COMMAND)))) {
        encrypt = 0;
    } else {
        fprintf(stderr, "command must be either %s or %s\n", ENCRYPT_COMMAND, DECRYPT_COMMAND);
        exit(1);
    }

    // check the number of arguments
    if ((encrypt == 1) && (ac != 6)) {
       fprintf(stderr, "%s must take exactly 5 arguments.\n", av[0]);
       exit(1); 
    }

    // initialize libwally
    if ((wally_init(0))) {
        fprintf(stderr, "libwally failed to initialize.\n");
        exit(1);
    }

    if ((ret = wally_hex_to_bytes(av[5], entropy, sizeof(entropy), &written)) != 0) {
        fprintf(stderr, "wally_hex_to_bytes failed with %d error code\n", ret);
        exit(1);
    }

    if (initializePRNG(entropy, sizeof(entropy))) {
        fprintf(stderr, "Failed to initialize PRNG\n");
        exit(1);
    }

    // copy all arguments
    pubkey_hex = strndup(av[2], strlen(av[2]));
    toEncrypt = strndup(av[3], strlen(av[3]));

    if ((ret = wally_hex_to_bytes(av[4], ephemeralPrivkey, sizeof(ephemeralPrivkey), &written)) != 0) {
        fprintf(stderr, "wally_hex_to_bytes failed with %d error code\n", ret);
        exit(1);
    }

    // TODO: sanity check on each argument

    // encrypt toEncrypt string
    cipher = encryptStringWithPubkey(pubkey_hex, toEncrypt, ephemeralPrivkey);

    if (!cipher) {
        fprintf(stderr, "encryptStringWithPubkey failed\n");
        exit(1);
    } else {
        printf("encrypted message:\n%s\n", cipher);
    }

    return 0;
}
