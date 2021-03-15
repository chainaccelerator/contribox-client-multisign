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
    unsigned char *bytes;
    int ret;
    size_t written;

    *bytes_len = strlen(hexstring) / 2;
    if (!(bytes = malloc(*bytes_len))) {
        fprintf(stderr, MEMORY_ERROR);
        return NULL;
    }

    if ((ret = wally_hex_to_bytes(hexstring, bytes, *bytes_len, &written)) != 0) {
        fprintf(stderr, "wally_hex_to_bytes failed with %d error code\n", ret);
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

uint32_t    *parseHdPath(const char *stringPath, size_t *path_len) {
    uint32_t    *hdPath;
    char        *path_copy;
    char        *saveptr;
    int         hardened = 0;
    size_t      counter = 0;
    char        *index = NULL;
    char        *last = NULL;

    if (!stringPath) {
        printf("no string to parse\n");
        return NULL;
    }

    // strtok will alter the original string, to prevent this we do a copy
    path_copy = strndup(stringPath, strlen(stringPath));

    saveptr = path_copy;

    // get the number of separator in order to allocate the uint array
    *path_len = 1; // we start at 1 since we're supposed to have at least 1 element
    while (*path_copy) {
        if (*path_copy == '/') {
            (*path_len)++;
        }
        path_copy++;
    }

    // allocate hdPath
    if (!(hdPath = calloc(*path_len, sizeof(*hdPath)))) {
        printf(MEMORY_ERROR);
        return NULL;
    }

    // reset the path_copy ptr to its initial position
    path_copy = saveptr;

    // split the string in tokens
    while ((index = strtok_r(path_copy, "/", &path_copy))) {
        hdPath[counter] = (uint32_t)strtol(index, &last, 10);
        if (hdPath[counter] >= BIP32_INITIAL_HARDENED_CHILD) {
            printf("each index can't be more than 2^31\n");
            goto cleanup;
        }
        if (*last && (strlen(last) == 1 && (*last == 'h' || *last == '\''))) {
            hardened = 1;
        } else if (*last) {
            printf("each index must end with a digit or \"h\" or \"'\"\n");
            goto cleanup;
        }
        if (hardened) {
            hdPath[counter] += BIP32_INITIAL_HARDENED_CHILD;
        }

        hardened = 0;
        counter++;
        last = NULL; 
    }

cleanup:
    clearThenFree(saveptr, strlen(saveptr));

    return hdPath;
}

unsigned char    *parseSignaturesList(const char *signatures_list, size_t *signatures_len) {
    unsigned char   *signatures = NULL;
    unsigned char   compactSignature[EC_SIGNATURE_LEN];
    unsigned char   *buffer = NULL;
    char            *list_copy = NULL;
    char            *saveptr = NULL;
    char            *der = NULL;
    int             ret = 1;
    size_t          counter = 0;
    size_t          written;

    if (!signatures_list) {
        fprintf(stderr, "Empty string to parseSignaturesList\n");
        return NULL;
    }

    // copy the string
    if (!(list_copy = strndup(signatures_list, strlen(signatures_list)))) {
        fprintf(stderr, "Failed to strndup the list\n");
        return NULL;
    }

    saveptr = list_copy;

    // count the number of signatures
    *signatures_len = sizeof(compactSignature); // we start at 1 since we're supposed to have at least 1 element
    while (*list_copy) {
        if (*list_copy == ' ') {
            (*signatures_len) += sizeof(compactSignature);
        }
        list_copy++;
    }

    // reset the list_copy ptr to its initial position
    list_copy = saveptr;

    // allocate signatures 
    if (!(signatures = calloc(*signatures_len, sizeof(*signatures)))) {
        fprintf(stderr, MEMORY_ERROR);
        goto cleanup;
    }

    // split the string
    while ((der = strtok_r(list_copy, " ", &list_copy))) {
        buffer = convertHexToBytes(der, &written);
        if ((ret = wally_ec_sig_from_der(buffer, written - 1, compactSignature, sizeof(compactSignature)))) {
            fprintf(stderr, "wally_ec_sig_from_der failed with %d error code\n", ret);
            goto cleanup;
        }
        memcpy(signatures + (counter * sizeof(compactSignature)), compactSignature, sizeof(compactSignature));

        clearThenFree(buffer, written);
        clearThenFree(der, strlen(der));
        counter++;
    }

cleanup:
    clearThenFree(saveptr, strlen(saveptr));

    return signatures;
}

struct ext_key *getChildFromXprv(const char *xprv, const uint32_t *hdPath, const size_t path_len) {
    struct ext_key *hdKey;
    struct ext_key *child;
    int ret;

    if ((ret = bip32_key_from_base58_alloc(xprv, &hdKey)) != 0) {
        printf("bip32_key_from_base58 failed with %d error code\n", ret);
        return NULL;
    };

    if ((ret = bip32_key_from_parent_path_alloc(hdKey, hdPath, path_len, BIP32_FLAG_KEY_PRIVATE, &child)) != 0) {
        printf("bip32_key_from_parent_path failed with %d error code\n", ret);
    }

    bip32_key_free(hdKey);

    return child;
}

struct ext_key *getChildFromXpub(const char *xpub, const uint32_t *hdPath, const size_t path_len) {
    struct ext_key *hdKey;
    struct ext_key *child;
    int ret;

    if ((ret = bip32_key_from_base58_alloc(xpub, &hdKey)) != 0) {
        printf("bip32_key_from_base58 failed with %d error code\n", ret);
        return NULL;
    };

    if ((ret = bip32_key_from_parent_path_alloc(hdKey, hdPath, path_len, BIP32_FLAG_KEY_PUBLIC, &child)) != 0) {
        printf("bip32_key_from_parent_path failed with %d error code\n", ret);
    }

    bip32_key_free(hdKey);

    return child;
}
