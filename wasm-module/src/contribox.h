#ifndef CONTRIBOX_H
#define CONTRIBOX_H

#include <string.h>

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

#define UNCONFIDENTIAL_ADDRESS_LIQUID_V1 "ex"
#define UNCONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST "ert"

#define CONFIDENTIAL_ADDRESS_LIQUID_V1 "lq"
#define CONFIDENTIAL_ADDRESS_ELEMENTS_REGTEST "el"

struct blindingInfo {
    unsigned char       *clearAsset; 
    unsigned char       *assetBlindingFactor;
    unsigned char       *valueBlindingFactor;
    uint64_t            clearValue;
    size_t              vout;
    struct blindingInfo *next;
};

#endif /*CONTRIBOX_H*/