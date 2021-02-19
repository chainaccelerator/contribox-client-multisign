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

function convertToString(ptr, label) {
  if (ptr === 0) {
    console.error("convertToString was given a NULL pointer for " + label);
    return "";
  }

  let str = UTF8ToString(ptr);

  if (ccall('wally_free_string', 'number', ['number'], [ptr]) !== 0) {
    console.error("ptr to " + str + " wasn't freed");
    return "";
  }

  if (str === "") {
    console.error("convertToString was given a pointer to an empty string for " + label);
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
    console.error("libwally is not build with elements");
    return -1;
  }

  return 0;
}

// this must be called when we're done, and will free all allocated memory
function cleanUp() {
  ccall('wally_cleanup', 'number', ['number'], [0]);
}

function generateWallet(mnemonic) {
  let passphrase = PASSPHRASE; // for now we can define passphrase as a constant, e.g. the application name.

  /** I don't think it's useful to leave the user choose a passphrase along with his seed, 
  *   I see it as an error prone and unecessary feature for our use case, user already have a userPassword to remember.
  *   It makes sense to define it as constant literal string to prevent collision between different applications.
  *   But this behaviour can easily be changed if necessary. 
  **/

  // generate the seed from the mnemonic
  if ((seed_ptr = ccall('generateSeed', 'number', ['string', 'string'], [mnemonic, passphrase])) === "") {
    console.error("generateMnemonic failed");
    return "";
  }

  if ((seed = convertToString(seed_ptr, "seed")) === "") {
    return "";
  }

  // generate a master key and serialize extended keys to base58
  if ((xprv_ptr = ccall('hdKeyFromSeed', 'number', ['string'], [seed])) === "") {
    console.error("hdKeyFromSeed failed");
    return "";
  }

  if ((xprv = convertToString(xprv_ptr, "xprv")) === "") {
    return "";
  }

  // derive the xpub from the xprv
  if ((xpub_ptr = ccall('xpubFromXprv', 'number', ['string'], [xprv])) === "") {
    console.error("xpubFromXprv failed");
    return "";
  };

  if ((xpub = convertToString(xpub_ptr, "xpub")) === "") {
    return "";
  }

  // write all the relevant data to our wallet obj
  let Wallet = {
    "xprv": xprv,
    "xpub": xpub,
    "hdPath": "0h/0", // we hardcode it for now
    "range": 100, // it means we'll use keys between 0h/0 and 0h/100
    "seedWords": mnemonic
  }
  
  // return the JSON string containing the wallet
  return JSON.stringify(Wallet);
}

function newWallet() {
  console.error("Creating new wallet");

  // First generate some entropy to generate the seed
  // FIXME: maybe it could be safer to move entropy generation on the wasm module side
  let entropy = new Uint8Array(32); // BIP39_ENTROPY_LEN_256
  window.crypto.getRandomValues(entropy);

  // generate a mnemonic (seed words) from this entropy
  if ((mnemonic_ptr = ccall('generateMnemonic', 'number', ['array', 'number'], [entropy, entropy.length])) === "") {
    console.error("generateMnemonic failed");
    return "";
  }

  // Overwrite the entropy used since we don't need it anymore
  window.crypto.getRandomValues(entropy);

  if ((mnemonic = convertToString(mnemonic_ptr, "mnemonic")) === "") {
    return "";
  }

  return generateWallet(mnemonic);
}

function restoreWallet(mnemonic) {
  return generateWallet(mnemonic);
}

function newAddressFromXpub(xpub, hdPath) {
  if ((pubkey_ptr = ccall('getPubkeyFromXpub', 'number', ['string', 'array'], [xpub, hdPath])) === 0) {
    console.error("getPubkeyFromXpub failed");
    return "";
  }

  if ((pubkey = convertToString(pubkey_ptr, "pubkey")) === "") {
    return "";
  }

  // get the unconfidential address
  if ((address_ptr = ccall('getAddressFromScript', 'number', ['string'], [pubkey])) === 0) {
    console.error("getAddressFromScript failed");
    return "";
  }

  if ((address = convertToString(address_ptr, "address")) === "") {
    return "";
  }

  let addressInfo = {
    unconfidentialAddress: address,
    pubkey: pubkey
  }

  return JSON.stringify(addressInfo);
}

function createIssueNftTx(previousTx, contractHash, assetAddress, changeAddress) {
  let newTx; 

  // call createTransactionWithNewAsset
  if ((newTx_ptr = ccall('createTransactionWithNewAsset', 'number', ['string', 'string', 'string', 'string', 'string', 'number'], [previousTx, contractHash, assetAddress, changeAddress])) === 0) {
    console.error("createBlindedTransactionWithNewAsset failed");
    return "";
  }

  if ((newTx = convertToString(newTx_ptr, "newTx")) === "") {
    return "";
  }

  return newTx;
}

function signIssueNftTx(unsignedTx, address, xprv, hdPath) {
  let signedTx_ptr;
  let signedTx;
  let signingKey_ptr;
  let signingKey;

  // find the right key 
  if ((signingKey_ptr = ccall('getSigningKey', 'number', ['string', 'string', 'array', 'number'], [xprv, address, path, path.length])) === "") {
    console.error("getSigningKey failed");
    return "";
  }

  if ((signingKey = convertToString(signingKey_ptr, "signingKey")) === "") {
    return "";
  }

  // sign the tx
  if ((signedTx_ptr = ccall('signProposalTx', 'number', ['string', 'string'], [unsignedTx, signingKey])) === "") {
    console.error("signProposalTx failed");
    return "";
  }

  if ((signedTx = convertToString(signedTx_ptr, "signedTx")) === "") {
    return "";
  }

  return signedTx;
}

function encryptHashWithPubkeys(message, pubkeys) {
  let cipher_list = [];

  for (var i = 0; i < pubkeys.length; i++) {
    var xpub = pubkeys[i].xpub;
    var hdPath = pubkeys[i].hdPath;
    var range = pubkeys[i].range;
    var encryptedProof_ptr;
    var encryptedProof;
    
    // derive a pubkey in the provided path
    if ((pubkey_ptr = ccall('getPubkeyFromXpub', 'number', ['string', 'string', 'number'], [hdPath, hdPath.length, range])) === 0) {
      console.error("getPubkeyFromXpub failed");
      return cipher_list = [];
    }
    
    if ((pubkey = convertToString(pubkey_ptr, "pubkey")) === "") {
      return cipher_list = [];
    }

    // encrypt the proof with the pubkey
    if ((encryptedProof_ptr = ccall('encryptProofWithPubkey', 'number', ['string', 'string'], [message, pubkey])) === 0) {
      console.error("encryptProofWithPubkey failed");
      return cipher_list = [];
    }

    if ((encryptedProof = convertToString(encryptedProof_ptr, "encryptedProof")) === "") {
      return cipher_list = [];
    }

    var newItem = {
      "encryptedProof": encryptedProof,
      "xpub": xpub,
      "hdPath": hdPath
    }
    cipher_list.push(newItem);
  }  

  return cipher_list;
}
