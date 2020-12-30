const BIP32_VER_MAIN_PRIVATE=parseInt("0x0488ADE4");
const BIP32_FLAG_KEY_PRIVATE=parseInt("0x0");
const BIP32_FLAG_KEY_PUBLIC=parseInt("0x1");
const BASE58_FLAG_CHECKSUM=parseInt("0x1");

function free_all(ptrs) {
  for (i = 0; i < ptrs.length; i++) {
    console.log("Freeing ptr " + i);
    Module._free(ptrs[i]);
  };
}

function init() {
  console.log("Initializing libwally");
  if (ccall("wally_init", 'number', ['number'], [0]) !== 0) {
    return -1;
  };

  console.log("Initializing PRNG");
  var entropy_ctx = new Uint8Array(32); // WALLY_SECP_RANDOMIZE_LEN
  window.crypto.getRandomValues(entropy_ctx);

  if (ccall("wally_secp_randomize", 'number', ['array', 'number'], [entropy_ctx, entropy_ctx.length]) !== 0) {
    return -1;
  };

  return 0;
}

function newWallet(userPassword) {
  console.log("Creating new wallet");
  let ptrs = [];
  let written = Module._malloc(4);
  let encryptedWallet = {
    integration: {
      share: {
        master: {
          xprv: "",
          xpub: "",
          range: [],
          seedWords: "",
          masterBlindingKey: "",
        }
      }
    }
  }
  
  // First generate some entropy to generate the seed
  let entropy = new Uint8Array(32); // BIP39_ENTROPY_LEN_256
  window.crypto.getRandomValues(entropy);

  // TODO: use pbkd with userPassword to get a key for aes encryption
  // generate a mnemonic (seed words) from this entropy
  if ((mnemonic = ccall('generateMnemonic', 'string', ['array', 'number'], [entropy, entropy.length])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  // Optional: show the seed words to the user.
  // alert("Ceci est la phrase de restauration de votre wallet,\nveuillez la noter soigneusement avant de fermer cette fenêtre.\n" + UTF8ToString(getValue(mnemonic_ptr, '*')));
  // encryptedWallet.integration.share.master.seedWords = UTF8ToString(getValue(mnemonic_ptr, '*'));
  // let mnemonic = UTF8ToString(getValue(mnemonic_ptr, '*'));

  alert("Ceci est la phrase de restauration de votre wallet,\nveuillez la noter soigneusement avant de fermer cette fenêtre.\n" + mnemonic);
  encryptedWallet.integration.share.master.seedWords = mnemonic;

  // generate the seed from the mnemonic
  let seed_ptr = Module._malloc(64);
  ptrs.push(seed_ptr);
  let seed = new Uint8Array(Module.HEAPU8.buffer, seed_ptr, 64); 
  if (ccall('bip39_mnemonic_to_seed', 'number', ['string', 'number', 'number', 'number', 'number'], [mnemonic, null, seed_ptr, seed.length, written]) !== 0 || 
  getValue(written) !== 64) {
    console.log("bip39_mnemonic_to_seed failed");
    return "";
  };

  // generate the master private key and blinding master key from the seed
  let masterKey_ptr = Module._malloc(200); // the number of bytes malloced here is not accurate, but good enough for now
  ptrs.push(masterKey_ptr);
  if (ccall('bip32_key_from_seed', 'number', ['array', 'number', 'number', 'number', 'number'], [seed, seed.length, BIP32_VER_MAIN_PRIVATE, 0, masterKey_ptr]) !== 0) {
    console.log("bip32_key_from_seed failed");
    return "";
  };
  
  // serialize extended private key to base58
  let xprv_ptr = Module._malloc(150); // the number of bytes malloced here is not accurate, but good enough for now
  ptrs.push(xprv_ptr);
  if (ccall('bip32_key_to_base58', 'number', ['number', 'number', 'number'], [masterKey_ptr, BIP32_FLAG_KEY_PRIVATE, xprv_ptr]) !== 0) {
    console.log("bip32_key_to_base58 failed");
    return "";
  };

  // format extended public key to base58
  let xpub_ptr = Module._malloc(150); // the number of bytes malloced here is not accurate, but good enough for now
  ptrs.push(xpub_ptr);
  if (ccall('bip32_key_to_base58', 'number', ['number', 'number', 'number'], [masterKey_ptr, BIP32_FLAG_KEY_PUBLIC, xpub_ptr]) !== 0) {
    console.log("bip32_key_to_base58 failed");
    return "";
  };

  // We compute the master blinding key
  let masterBlindingKey_ptr = Module._malloc(64);
  ptrs.push(masterBlindingKey_ptr);
  let masterBlindingKey = new Uint8Array(Module.HEAPU8.buffer, masterBlindingKey_ptr, 64); 
  if (ccall('wally_asset_blinding_key_from_seed', 'number', ['number', 'number', 'number', 'number'], [seed_ptr, seed.length, masterBlindingKey_ptr, masterBlindingKey.length]) !== 0) {
    console.log("wally_asset_blinding_key_from_seed failed");
    return "";
  }

  // format master blinding key to hex
  let masterBlindingKey_hex = Module._malloc((masterBlindingKey.length * 2) + 1);
  ptrs.push(masterBlindingKey_hex);
  if (ccall('wally_hex_from_bytes', 'number', ['number', 'number', 'number'], [masterBlindingKey_ptr, masterBlindingKey.length, masterBlindingKey_hex]) !== 0) {
    console.log("wally_hex_from_bytes failed");
    return "";
  };
  
  // write all the relevant data to our wallet obj
  encryptedWallet.integration.share.master.xprv = UTF8ToString(getValue(xprv_ptr, '*'));
  encryptedWallet.integration.share.master.xpub = UTF8ToString(getValue(xpub_ptr, '*'));
  encryptedWallet.integration.share.master.masterBlindingKey= UTF8ToString(getValue(masterBlindingKey_hex, '*'));
  

  // free the string alloced by Libwally
  if (ccall('wally_free_string', 'number', ['number'], [masterKey_ptr]) !== 0) {
    console.log("Libwally failed to free masterkey");
    return "";
  };
  if (ccall('wally_free_string', 'number', ['number'], [masterBlindingKey_hex]) !== 0) {
    console.log("Libwally failed to free masterkey");
    return "";
  };

  // free the string we malloced here
  free_all(ptrs)

  // return the wallet obj in JSON format
  return JSON.stringify(encryptedWallet);
}
