const PASSPHRASE = "";

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

  let passphrase = PASSPHRASE; // for now we can define passphrase as a constant, e.g. the application name.

/*   I don't think it's useful to leave the user choose a passphrase along with his seed, 
  I see it as an error prone and unecessary feature for our use case, user already have a userPassword to remember.
  It makes sense to define it as constant literal string to prevent collision between different applications.
  But this behaviour can easily be changed if necessary. */

  // generate the seed from the mnemonic
  if ((seed_ptr = ccall('generateSeed', 'number', ['string', 'string'], [mnemonic, passphrase])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  let seed_hex = UTF8ToString(seed_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [seed_ptr]) !== 0) {
    console.log("seed_ptr wasn't freed");
    return "";
  }

  // generate a master key and serialize extended keys to base58
  if ((xprv_ptr = ccall('hdKeyFromSeed', 'number', ['string'], [seed_hex])) === "") {
    console.log("hdKeyFromSeed failed");
    return "";
  }

  let xprv = UTF8ToString(xprv_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [xprv_ptr]) !== 0) {
    console.log("xprv_ptr wasn't freed");
    return "";
  }

  // We compute the master blinding key
  if ((masterBlindingKey_ptr = ccall('generateMasterBlindingKey', 'number', ['string'], [seed_hex])) === "") {
    console.log("generateMasterBlindingKey failed");
    return "";
  }

  let masterBlindingKey_hex = UTF8ToString(masterBlindingKey_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [masterBlindingKey_ptr]) !== 0) {
    console.log("masterBlindingKey_ptr wasn't freed");
    return "";
  }

  // write all the relevant data to our wallet obj
  Wallet.xprv = xprv;
  Wallet.masterBlindingKey= masterBlindingKey_hex;
  Wallet.seedWords = mnemonic;
  
  // Encrypt the wallet in Json form with user password
  if ((encryptedWallet_ptr = ccall('encryptFileWithPassword', 'number', ['string', 'string'], [userPassword, JSON.stringify(Wallet)])) === "") {
    console.log("encryptFileWithPassword failed");
    return "";
  }

  let encryptedWallet = UTF8ToString(encryptedWallet_ptr);

  // free the string malloced by libwally
  if (ccall('wally_free_string', 'number', ['number'], [encryptedWallet_ptr]) !== 0) {
    console.log("encryptedWallet_ptr wasn't freed");
    return "";
  }

  // return the wallet obj in JSON format
  return encryptedWallet;
}

function newWallet(userPassword) {
  console.log("Creating new wallet");

  // First generate some entropy to generate the seed
  // FIXME: maybe it could be safer to move entropy generation on the wasm module side
  let entropy = new Uint8Array(32); // BIP39_ENTROPY_LEN_256
  window.crypto.getRandomValues(entropy);

  // generate a mnemonic (seed words) from this entropy
  if ((mnemonic_ptr = ccall('generateMnemonic', 'number', ['array', 'number'], [entropy, entropy.length])) === "") {
    console.log("generateMnemonic failed");
    return "";
  }

  // Overwrite the entropy used since we don't need it anymore
  window.crypto.getRandomValues(entropy);

  let mnemonic = UTF8ToString(mnemonic_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [mnemonic_ptr]) !== 0) {
    console.log("mnemonic wasn't freed");
    return "";
  }

  return generateWallet(userPassword, mnemonic);
}

function restoreWallet(userPassword, mnemonic) {
  return generateWallet(userPassword, mnemonic);
}

function decryptWallet(encryptedWallet, userPassword) {
  if ((clearWallet_ptr = ccall('decryptFileWithPassword', 'number', ['string', 'string'], [encryptedWallet, userPassword])) === "") {
    console.log("decryptFileWithPassword failed");
    return "";
  };

  let clearWallet = UTF8ToString(clearWallet_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [clearWallet_ptr]) !== 0) {
    console.log("mnemonic wasn't freed");
    return "";
  }

  try {
    JSON.parse(clearWallet);
  } catch(e) {
    console.log("Can't decrypt the wallet.");
    if (e instanceof SyntaxError) {
      alert("Failed to decrypt your wallet, check your password and try again.");
    }
    else {
      alert("Unknwon Error: " + e);
    }
    return "";
  }

  return clearWallet;
}

function getXpub(encryptedWallet, userPassword) {
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let wallet_obj = JSON.parse(clearWallet);

  if ((xpub_ptr = ccall('xpubFromXprv', 'number', ['string'], [wallet_obj.xprv])) === "") {
    console.log("xpubFromXprv failed");
    return "";
  };

  let xpub = UTF8ToString(xpub_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [xpub_ptr]) !== 0) {
    console.log("xpub wasn't freed");
    return "";
  }

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

function newConfidentialAddress(script, encryptedWallet, userPassword) {
  // get the master blinding key
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let masterBlindingKey;
  {
    let wallet_obj = JSON.parse(clearWallet);
    masterBlindingKey = wallet_obj.masterBlindingKey;
  }

  // get the blinding key
  if ((privateBlindingKey_ptr = ccall('getBlindingKeyFromScript', 'number', ['string', 'string'], [script, masterBlindingKey])) === "") {
    console.log("getBlindingKeyFromScript failed");
    return "";
  }

  let privateBlindingKey = UTF8ToString(privateBlindingKey_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [privateBlindingKey_ptr]) !== 0) {
    console.log("private blinding key wasn't freed");
    return "";
  }

  // get the unconfidential address
  if ((address_ptr = ccall('getAddressFromScript', 'number', ['string'], [script])) === "") {
    console.log("getaddressFromScript failed");
    return "";
  }

  let address = UTF8ToString(address_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [address_ptr]) !== 0) {
    console.log("address wasn't freed");
    return "";
  }

  // create the confidential address out of the key and the address
  if ((confidentialAddress_ptr = ccall('getConfidentialAddressFromAddress', 'number', ['string', 'string'], [address, privateBlindingKey])) === "") {
    console.log("getConfidentialAddressFromAddress failed");
    return "";
  }

  let confidentialAddress = UTF8ToString(confidentialAddress_ptr);

  if (ccall('wally_free_string', 'number', ['number'], [confidentialAddress_ptr]) !== 0) {
    console.log("confidentialAddress wasn't freed");
    return "";
  }

  let confidentialInfo = {
    confidentialAddress: confidentialAddress,
    privateBlindingKey: privateBlindingKey,
    unconfidentialAddress: address
  }

  return JSON.stringify(confidentialInfo);

}
