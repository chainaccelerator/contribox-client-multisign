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

function generateWallet(userPassword, mnemonic) {
  let Wallet = {
      xprv: "",
      seedWords: "",
      masterBlindingKey: ""
  }

  // generate the seed from the mnemonic
  if ((seed_hex = ccall('generateSeed', 'string', ['string'], [mnemonic])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  // generate a master key and serialize extended keys to base58
  if ((xprv = ccall('hdKeyFromSeed', 'string', ['string'], [seed_hex])) === "") {
    console.log("hdKeyFromSeed failed");
    return "";
  }

  // We compute the master blinding key
  if ((masterBlindingKey_hex = ccall('generateMasterBlindingKey', 'string', ['string'], [seed_hex])) === "") {
    console.log("generateMasterBlindingKey failed");
    return "";
  }

  // write all the relevant data to our wallet obj
  Wallet.xprv = xprv;
  Wallet.masterBlindingKey= masterBlindingKey_hex;
  Wallet.seedWords = mnemonic;
  
  // Encrypt the wallet in Json form with user password
  let encryptedWallet_ptr = Module._malloc(32);
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
  Module._free(encryptedWallet_ptr);

  // return the wallet obj in JSON format
  return encryptedWallet;
}

function newWallet(userPassword) {
  console.log("Creating new wallet");

  // First generate some entropy to generate the seed
  let entropy = new Uint8Array(32); // BIP39_ENTROPY_LEN_256
  window.crypto.getRandomValues(entropy);

  // generate a mnemonic (seed words) from this entropy
  if ((mnemonic = ccall('generateMnemonic', 'string', ['array', 'number'], [entropy, entropy.length])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  window.crypto.getRandomValues(entropy);
  // Optional: show the seed words to the user.
  alert("Ceci est la phrase de restauration de votre wallet,\nveuillez la noter soigneusement avant de fermer cette fenêtre.\n" + mnemonic);

  return generateWallet(userPassword, mnemonic);
}

function restoreWallet(userPassword, mnemonic) {
  return generateWallet(userPassword, mnemonic);
}

function decryptWallet(encryptedWallet, userPassword) {
  if ((clear_len = ccall('getClearLenFromCipher', 'number', ['string'], [encryptedWallet])) <= 0) {
    console.log("getClearLenFromCipher failed");
    return "";
  };
  let clearWallet_ptr = Module._malloc(clear_len);
  if ((clearWallet = ccall('decryptFileWithPassword', 'string', ['string', 'string', 'number'], [encryptedWallet, userPassword, clearWallet_ptr])) === "") {
    console.log("decryptFileWithPassword failed");
    return "";
  };

  Module._free(clearWallet_ptr);

  return clearWallet;
}

function getXpub(encryptedWallet, userPassword) {
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let wallet_obj = JSON.parse(clearWallet);

  if ((xpub = ccall('xpubFromXprv', 'string', ['string'], [wallet_obj.xprv])) === "") {
    console.log("xpubFromXprv failed");
    return "";
  };

  return xpub;
}

function getSeed(encryptedWallet, userPassword) {
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let wallet_obj = JSON.parse(clearWallet);

  return wallet_obj.seedWords;
}
