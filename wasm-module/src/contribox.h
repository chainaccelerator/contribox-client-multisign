#ifndef CONTRIBOX_H
#define CONTRIBOX_H

#include <string.h>

#include "./ccan/hex/hex.h"

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
// #include "../libwally/include/wally.hpp"

struct WalletKeys {
    char *xprv;
    char *xpub;
    unsigned char *masterBlindingKey;
    char **seed_words;
}; // the struct that contains all the new wallet data that we will return in json string.

// Call once at startup before calling any other libwally functions. Must return (int)0.
int init();

/**
 * We call this only once if there's no known wallet. 
 * entropy_hex is 32 or 64B entropy in hex string. It is used to generate the keys and then discarded.
 * userPassword is the password chosen by user on wallet creation. Keys will be encrypted using this password.
 * It must only contains ASCII characters for now.
 * We return a json string containing an encrypted string representation of the config file, and string base58 representation of the xpub.
 */
// int newWallet(const char *entropy_hex);
// char *newWallet(const char *entropy_hex, const char *userPassword);

#endif /*CONTRIBOX_H*/