# include "emscripten.h"
# include "contribox.h"
# include <stdio.h>
# include <time.h>
# include <stdlib.h>

EMSCRIPTEN_KEEPALIVE
int init() {
    uint32_t flag = 0;
    if (wally_init(flag) != 0) {
        return -1;
    }
    return 0;
}

/* char *generateAesKey(const char *user_password) {
    char *base58_key;
    unsigned char *key;

    // maybe there's not a real use case for scrypt here
    // wally_scrypt(user_password, strlen(user_password), NULL, (size_t)0, 16384, 8, 1, key, 32);
    wally_sha256d(user_password, )
} */

/* EMSCRIPTEN_KEEPALIVE
char *encryptConfig(const unsigned char *password, char *clearConfig) {
    char *encryptedConfig
    // generate the AES key
    wally_scrypt(password, strlen(password))
    return encryptedConfig;
} */

EMSCRIPTEN_KEEPALIVE
char *newWallet(const char *entropy_hex) {
// char *newWallet(const char *entropy_hex, const char *userPassword) {
    // 97169adfc06fc39be680b0bb3594a90f222b15286a1484a95abcf272d2237be8
    struct WalletKeys newWallet; 
    const unsigned char entropy[hex_data_size(strlen(entropy_hex))]; // given entropy in bytes.
    const unsigned char *seed; // generated from the seed_words.
    size_t written; // number of Bytes returned by some functions.
    struct ext_key *xprv; // extended private key, "master" key from which we can derive all the others.
    unsigned char *masterBlindingKey; // 64B that we will use to create blinding keys for each output.
    // char *password;
    char *salt;
    int ret = 0;
    // TODO: should we use pbkdf2_hmac_sha256, since both entropy and salt will be given by the browser anyway?
    // TODO: check the length of entropy, even if libwally should catch it if it's wrong
    char **seed_words;
    // we first need to turn the hex string into bytes.
    if (!hex_decode(entropy_hex, strlen(entropy_hex), entropy, sizeof(entropy)))
        return "Failed";
    // now we can use the entropy to generate seed words, also called "mnemonic".
    printf("len of entropy is %lu\n", sizeof(entropy));
    if ((ret = bip39_mnemonic_from_bytes(NULL, entropy, (size_t)sizeof(entropy), seed_words)) != 0) {
        printf("mnemonic generation failed with %d error code\n", ret);
        return "Failed";
    }
    // with this mnemonic we can now generate a seed.
    if (bip39_mnemonic_to_seed(*(newWallet.seed_words), NULL, seed, BIP39_SEED_LEN_512, &written) != 0)
        return "seed generation failed";
    // // from the seed we generate the xprv, which is 64B long.
    // bip32_key_from_seed(seed, BIP39_SEED_LEN_512, BIP32_VER_MAIN_PRIVATE, 0, xprv);
    // // from the same seed, we generate the master blinding key.
    // // wally_asset_blinding_key_from_seed(seed, BIP32_ENTROPY_LEN_512, masterBlindingKey, HMAC_SHA512_LEN);
    // // newWallet.masterBlindingKey = masterBlindingKey;
    // // format xprv as a string and add it to newWallet
    // bip32_key_to_base58(xprv, BIP32_FLAG_KEY_PRIVATE, &(newWallet.xprv));
    // // generate the corresponding extended public key, or xpub, and format it in base 58.
    // bip32_key_to_base58(xprv, BIP32_FLAG_KEY_PUBLIC, &(newWallet.xpub));
    // need to convert struct to json string
    return "Success";
}

