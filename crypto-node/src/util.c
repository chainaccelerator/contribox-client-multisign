#include "contribox.h"

void    clearThenFree(void *p, size_t len) {
    if (p) {
        memset(p, '\0', len);
        free(p);
        p = NULL;
    }
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
