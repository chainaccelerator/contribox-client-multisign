function free_all(ptrs) {
  for (i = 0; i < ptrs.length; i++) {
    Module._free(ptrs[i]);
  };
}

function hexStringToByte(str) {
  if (!str) {
    return new Uint8Array();
  }
  
  var a = [];
  for (var i = 0, len = str.length; i < len; i+=2) {
    a.push(parseInt(str.substr(i,2),16));
  }
  
  return new Uint8Array(a);
}

function toHexString(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

function init() {
  console.log("Initializing libwally");
  if (ccall("wally_init", 'number', ['number'], [0]) !== 0) {
    return -1;
  };

  console.log("Initializing PRNG");
  let entropy_ctx = new Uint8Array(32); // WALLY_SECP_RANDOMIZE_LEN
  window.crypto.getRandomValues(entropy_ctx);

  if (ccall("wally_secp_randomize", 'number', ['array', 'number'], [entropy_ctx, entropy_ctx.length]) !== 0) {
    return -1;
  };

  console.log("Checking that libwally has been compiled with elements");
  let is_elements = ccall('is_elements', 'number', [], [])

  if (is_elements !== 1) {
    console.log("libwally is not build with elements");
    return -1;
  }

  return 0;
}

function newWallet(userPassword) {
  console.log("Creating new wallet");
  let ptrs = [];
  let Wallet = {
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

  // generate a mnemonic (seed words) from this entropy
  if ((mnemonic = ccall('generateMnemonic', 'string', ['array', 'number'], [entropy, entropy.length])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  // Optional: show the seed words to the user.
  alert("Ceci est la phrase de restauration de votre wallet,\nveuillez la noter soigneusement avant de fermer cette fenêtre.\n" + mnemonic);
  Wallet.integration.share.master.seedWords = mnemonic;

  // generate the seed from the mnemonic
  if ((seed_hex = ccall('generateSeed', 'string', ['string'], [mnemonic])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  let seed = hexStringToByte(seed_hex);

  // generate a master key and serialize extended keys to base58
  if ((xprv = ccall('hdKeyFromSeed', 'string', ['string'], [seed_hex])) === "") {
    console.log("hdKeyFromSeed failed");
    return "";
  }

  if ((xpub = ccall('xpubFromXprv', 'string', ['string'], [xprv])) === "") {
    console.log("xpubFromXprv failed");
    return "";
  }

  // We compute the master blinding key
  let masterBlindingKey_ptr = Module._malloc(64);
  ptrs.push(masterBlindingKey_ptr);
  let masterBlindingKey = new Uint8Array(Module.HEAPU8.buffer, masterBlindingKey_ptr, 64); 
  if (ccall('wally_asset_blinding_key_from_seed', 'number', ['array', 'number', 'number', 'number'], [seed, seed.length, masterBlindingKey_ptr, masterBlindingKey.length]) !== 0) {
    console.log("wally_asset_blinding_key_from_seed failed");
    return "";
  }

  // if ((masterBlindingKey_hex = ccall('generateMasterBlindingKey', 'string', ['array'], [seed])) === "") {
  //   console.log("generateMasterBlindingKey failed");
  //   return "";
  // }

  // format master blinding key to hex
  let masterBlindingKey_hex = toHexString(masterBlindingKey);
  
  // write all the relevant data to our wallet obj
  Wallet.integration.share.master.xprv = xprv;
  Wallet.integration.share.master.xpub = xpub;
  Wallet.integration.share.master.masterBlindingKey= masterBlindingKey_hex;
  
  // Encrypt the wallet in Json form with user password
  let encryptedWallet_ptr = Module._malloc(32);
  ptrs.push(encryptedWallet_ptr);
  if ((encryptedWallet = ccall('encryptFileWithPassword', 'string', ['string', 'string', 'number'], [userPassword, JSON.stringify(Wallet), encryptedWallet_ptr])) === "") {
    console.log("encryptFileWithPassword failed");
    return "";
  }

  // free the string malloced by libwally
  if (ccall('wally_free_string', 'number', ['number'], [encryptedWallet_ptr]) !== 0) {
    console.log("encryptedWallet_ptr wasn't freed");
    return "";
  }

  // free the string we malloced here
  free_all(ptrs)

  // return the wallet obj in JSON format
  return encryptedWallet;
}

function decryptWallet(encryptedWallet, userPassword) {
  console.log("Entering decryptWallet");

  if ((clearWallet = ccall('decryptFileWithPassword', 'string', ['string', 'string'], [encryptedWallet, userPassword])) === "") {
    console.log("decryptFileWithPassword failed");
    return "";
  };

  return JSON.stringify(clearWallet);
}
