#ifndef CONTRIBOX_H
#define CONTRIBOX_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "../libwally/include/wally_address.h"
#include "../libwally/include/wally_bip32.h"
#include "../libwally/include/wally_bip38.h"
#include "../libwally/include/wally_bip39.h"
#include "../libwally/include/wally_core.h"
#include "../libwally/include/wally_crypto.h"
#include "../libwally/include/wally_elements.h"
#include "../libwally/include/wally_psbt.h"
#include "../libwally/include/wally_script.h"
#include "../libwally/include/wally_symmetric.h"
#include "../libwally/include/wally_transaction.h"

#define MEMORY_ERROR "memory allocation error\n"

#define ENCRYPT_COMMAND "encrypt"
#define DECRYPT_COMMAND "decrypt"

#define ENCRYPT_ARGUMENTS 6
#define DECRYPT_ARGUMENTS 6

// util.c
void            clearThenFree(void *p, size_t len);
/** Fill an array of array_len size with random bytes
*   THIS IS NOT CRYPTOGRAPHICALLY SECURE, we use the rand() function
*   Use this function to generate randomness that is somewhat less critical, blinding factors and initialzation vector for AES encryption.
*   We use the browser PRNG for seed generation.
*   FIXME: either use the PRNG of the browser (a bit cumbersome), or add another dependency (libsodium?) with a proper PRNG.
**/
void            getRandomBytes(unsigned char *array, const size_t array_len);

/*  allocate and return a new byte string that contains the same byte sequence in reverse order
bitcoin and elements do love to reverse bytes sequence like hashes
BE CAREFUL */
void            *reverseBytes(const unsigned char *bytes, const size_t bytes_len);

unsigned char   *convertHexToBytes(const char *hexstring, size_t *bytes_len);

/** This is useful if we need to input some data that are usually printed out in reverse order by bitcoin/elements
*   like usually are the txid, asset id, and other hashes.
**/
unsigned char   *reversedBytesFromHex(const char *hexString, size_t *bytes_len);
void            printBytesInHex(const unsigned char *toPrint, const size_t len, const char *label);

/** this can be useful when we need to print out values that are usually printed in reverse by bitcoin/elements */
void            printBytesInHexReversed(const unsigned char *toPrint, const size_t len, const char *label);

// crypto.c
unsigned char   *encryptWithAes(const char *toEncrypt, const unsigned char *key, size_t *cipher_len);
char            *decryptWithAes(const char *toDecrypt, const unsigned char *key);

#endif /*CONTRIBOX_H*/