const PASSPHRASE = "";
const HARDENED_INDEX = Math.pow(2, 31);

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

function convertToString(ptr) {
  let str = UTF8ToString(ptr);

  if (ccall('wally_free_string', 'number', ['number'], [ptr]) !== 0) {
    console.error("ptr to " + str + " wasn't freed");
    return "";
  }

  return str;
}

// this must be called once before calling any other functions below
function init() {
  console.log("Initializing libwally");
  if (ccall("wally_init", 'number', ['number'], [0]) !== 0) {
    return -1;
  };

  console.log("Initializing PRNG");
  let entropy_ctx = new Uint8Array(32); // WALLY_SECP_RANDOMIZE_LEN
  window.crypto.getRandomValues(entropy_ctx);

  if (ccall("initializePRNG", 'number', ['array', 'number'], [entropy_ctx, entropy_ctx.length]) !== 0) {
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

// this must be called when we're done, and will free all allocated memory
function cleanUp() {
  ccall('wally_cleanup', 'number', ['number'], [0]);
}

function parsePath(hdPath) {
  // split the hdPath string
  rawPath = hdPath.split("/");

  let path = rawPath.map(function(x) {
    let hardened = false;
    if (x.charAt(x.length - 1) === 'h' || x.charAt(x.length - 1) === '\'') {
      hardened = true;
      x = x.slice(0, -1);
    }
    var reg = new RegExp('^[0-9]+$');
    if (!reg.test(x)) {
      console.error("path is incorrect: must only contain numeric characters");
      return -1;
    }
    if (Number(x) >= HARDENED_INDEX) {
      console.error("path is incorrect: index must be less than 2^31");
      return -1;
    }
    if (hardened) {
      return Number(x) + HARDENED_INDEX;
    }
    return Number(x);
  });

  // check that all index is > 0
  if (!path.every(function(x) {
    return x >= 0;
  })) {
    return "";
  }

  return path;
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
  // get the xprv from the encrypted wallet and compute the xpub from it
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
  // get the seed from encrypted wallet
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let wallet_obj = JSON.parse(clearWallet);

  return wallet_obj.seedWords;
}

function getMasterBlindingKey(encryptedWallet, userPassword) {
  // get the master blinding key
  if ((clearWallet = decryptWallet(encryptedWallet, userPassword)) === "") {
    console.log("decryptWallet failed");
    return "";
  }
  
  let wallet_obj = JSON.parse(clearWallet);

  return wallet_obj.masterBlindingKey;
}

function newConfidentialAddressFromScript(script, encryptedWallet, userPassword) {
  // Compute a new confidential address from a multisig script
  if ((masterBlindingKey = getMasterBlindingKey(encryptedWallet, userPassword)) === "") {
    console.error("getMasterBlindingKey failed");
    return "";
  }

  // get the blinding key
  if ((privateBlindingKey_ptr = ccall('getBlindingKeyFromScript', 'number', ['string', 'string'], [script, masterBlindingKey])) === 0) {
    console.error("getBlindingKeyFromScript failed");
    return "";
  }

  if ((privateBlindingKey = convertToString(privateBlindingKey_ptr)) === "") {
    console.error("Failed to convert newTx to string");
    return "";
  }

  // get the unconfidential address
  if ((address_ptr = ccall('getAddressFromScript', 'number', ['string'], [script])) === "") {
    console.error("getaddressFromScript failed");
    return "";
  }

  if ((address = convertToString(address_ptr)) === "") {
    console.error("Failed to convert newTx to string");
    return "";
  }

  // create the confidential address out of the key and the address
  if ((confidentialAddress_ptr = ccall('getConfidentialAddressFromAddress', 'number', ['string', 'string'], [address, privateBlindingKey])) === "") {
    console.error("getConfidentialAddressFromAddress failed");
    return "";
  }

  if ((confidentialAddress = convertToString(confidentialAddress_ptr)) === "") {
    console.error("Failed to convert newTx to string");
    return "";
  }

  let confidentialInfo = {
    confidentialAddress: confidentialAddress,
    privateBlindingKey: privateBlindingKey,
    // scriptPubkey: scriptPubkey,
    unconfidentialAddress: address
  }

  return JSON.stringify(confidentialInfo);
}

function newConfidentialAddressFromXpub(xpub, hdPath, encryptedWallet, userPassword) {
  let path = parsePath(hdPath);

  if ((pubkey_ptr = ccall('getPubkeyFromXpub', 'number', ['string', 'array', 'number'], [xpub, path, path.length])) === 0) {
    console.log("getPubkeyFromXpub failed");
    return "";
  }

  if ((pubkey = convertToString(pubkey_ptr)) === "") {
    console.error("Failed to convert pubkey to string");
    return "";
  }

  if ((masterBlindingKey = getMasterBlindingKey(encryptedWallet, userPassword)) === "") {
    console.log("getMasterBlindingKey failed");
    return "";
  }

  // get the blinding key
  if ((privateBlindingKey_ptr = ccall('getBlindingKeyFromScript', 'number', ['string', 'string'], [pubkey, masterBlindingKey])) === 0) {
    console.log("getBlindingKeyFromScript failed");
    return "";
  }

  if ((privateBlindingKey = convertToString(privateBlindingKey_ptr)) === "") {
    console.error("Failed to convert privateBlindingKey to string");
    return "";
  }

  // get the unconfidential address
  if ((address_ptr = ccall('getAddressFromScript', 'number', ['string'], [pubkey])) === 0) {
    console.log("getAddressFromScript failed");
    return "";
  }

  if ((address = convertToString(address_ptr)) === "") {
    console.error("Failed to convert address to string");
    return "";
  }

  // combine both to get a confidential address
  if ((confidentialAddress_ptr = ccall('getConfidentialAddressFromAddress', 'number', ['string', 'string'], [address, privateBlindingKey])) === 0) {
    console.log("getConfidentialAddressFromAddress failed");
    return "";
  }

  if ((confidentialAddress = convertToString(confidentialAddress_ptr)) === "") {
    console.error("Failed to convert confidentialAddress to string");
    return "";
  }

  let confidentialInfo = {
    confidentialAddress: confidentialAddress,
    privateBlindingKey: privateBlindingKey,
    unconfidentialAddress: address,
    pubkey: pubkey
  }

  return JSON.stringify(confidentialInfo);
}

function createProposalTx(previousTx, contractHash, assetAddress, changeAddress, encryptedWallet, userPassword, blind) {
  let masterBlindingKey;
  let newTx; 

  // FIXME: check if the provided addresses are confidential if blind == 1, fail now if one or both are not.

  // get the master blinding key
  if ((masterBlindingKey = getMasterBlindingKey(encryptedWallet, userPassword)) === "") {
    console.error("getMasterBlindingKey failed");
    return "";
  }

  // call createTransactionWithNewAsset with the righ blind flag
  if ((newTx_ptr = ccall('createTransactionWithNewAsset', 'number', ['string', 'string', 'string', 'string', 'string', 'number'], [previousTx, contractHash, masterBlindingKey, assetAddress, changeAddress, blind])) === 0) {
    console.error("createBlindedTransactionWithNewAsset failed");
    return "";
  }

  if ((newTx = convertToString(newTx_ptr)) === "") {
    console.error("Failed to convert newTx to string");
    return "";
  }

  return newTx;
}

function decodeTx(Tx) {
  if ((ccall('txIsValid', 'number', ['string'], [Tx])) != 0) {
    return "Tx can't be decoded";
  }

  return "OK";
}
