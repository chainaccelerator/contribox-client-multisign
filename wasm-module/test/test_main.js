function test_generateMnemonic() {
  // open the test file
  let test_vectors = FS.readFile('test/bip39_test_vectors.json', { "encoding": "utf8" });
  // for each item in the list :
  // generateMnemonic from entropy
  let test_obj = JSON.parse(test_vectors);
  let wrong_mnemonics = "";

  Object.keys(test_obj).every(key => {
    let entropy = hexStringToByte(key);
    if ((mnemonic_ptr = ccall('generateMnemonic', 'number', ['array', 'number'], [entropy, entropy.length])) === "") {
      console.log("generateMnemonic failed");
      return "test_generateMnemonic KO: generateMnemonic failed";
    }

    let mnemonic = UTF8ToString(mnemonic_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [mnemonic_ptr]) !== 0) {
      console.log("mnemonic wasn't freed");
      return "";
    }

    if (mnemonic === test_obj[key][0]) {
      console.log("OK");
      return true;
    } else {
      console.log(mnemonic + " doesn't match " + test_obj[key][0]);
      wrong_mnemonics += key;
      wrong_mnemonics += " ";
      return true;
    }
  })
  if (wrong_mnemonics !== "") {
    return "test_generateMnemonic KO: mnemonic don't match\nwrong mnemonics: " + wrong_mnemonics;
  }
  return "test_generateMnemonic OK: all generated mnemonics match";
}

function test_generateSeed() {
  // open the test file
  let test_vectors = FS.readFile('test/bip39_test_vectors.json', { "encoding": "utf8" });
  // for each item in the list :
  // generateMnemonic from entropy
  // generateSeed from mnemonic
  let test_obj = JSON.parse(test_vectors);
  let wrong_seeds = "";

  Object.keys(test_obj).every(key => {
    entropy = hexStringToByte(key);
    if ((mnemonic_ptr = ccall('generateMnemonic', 'number', ['array', 'number'], [entropy, entropy.length])) === "") {
      console.log("generateMnemonic failed");
      return "test_generateMnemonic KO: generateMnemonic failed";
    }

    let mnemonic = UTF8ToString(mnemonic_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [mnemonic_ptr]) !== 0) {
      console.log("mnemonic wasn't freed");
      return "";
    }

    let passphrase = "TREZOR";

    if ((seed_ptr = ccall('generateSeed', 'number', ['string', 'string'], [mnemonic, passphrase])) === "") {
      console.log("generateSeed failed");
      return "test_generateSeed KO: generateSeed failed";
    }

    let seed_hex = UTF8ToString(seed_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [seed_ptr]) !== 0) {
      console.log("seed wasn't freed");
      return "";
    }

    if (seed_hex === test_obj[key][1]) {
      console.log("OK");
      return true;
    } else {
      console.log(seed_hex + " doesn't match " + test_obj[key][1]);
      console.log("mnemonic is " + mnemonic);
      wrong_seeds += key;
      wrong_seeds += " ";
      return true;
    }
  })

  if (wrong_seeds !== "") {
    return "test_generateSeed KO: seeds don't match\nwrong key: " + wrong_seeds;
  }
  return "test_generateSeed OK: all generated seeds match";
}

function test_hdKeyFromSeed() {
  // open the test file
  let test_vectors = FS.readFile('test/bip39_test_vectors.json', { "encoding": "utf8" });
  // for each item in the list :
  // generateMnemonic from entropy
  // generateSeed from mnemonic
  // hdKeyFromSeed from seed
  let test_obj = JSON.parse(test_vectors);
  let wrong_xprv = "";

  Object.keys(test_obj).every(key => {
    entropy = hexStringToByte(key);
    if ((mnemonic_ptr = ccall('generateMnemonic', 'number', ['array', 'number'], [entropy, entropy.length])) === "") {
      console.log("generateMnemonic failed");
      return "test_generateMnemonic KO: generateMnemonic failed";
    }

    let mnemonic = UTF8ToString(mnemonic_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [mnemonic_ptr]) !== 0) {
      console.log("mnemonic wasn't freed");
      return "";
    }

    let passphrase = "TREZOR";

    if ((seed_ptr = ccall('generateSeed', 'number', ['string', 'string'], [mnemonic, passphrase])) === "") {
      console.log("generateSeed failed");
      return "test_generateSeed KO: generateSeed failed";
    }

    let seed_hex = UTF8ToString(seed_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [seed_ptr]) !== 0) {
      console.log("seed wasn't freed");
      return "";
    }

    if ((xprv_ptr = ccall('hdKeyFromSeed', 'number', ['string'], [seed_hex])) === "") {
      console.log("hdKeyFromSeed failed");
      return false;
    }

    let xprv = UTF8ToString(xprv_ptr);

    if (ccall('wally_free_string', 'number', ['number'], [xprv_ptr]) !== 0) {
      console.log("seed wasn't freed");
      return "";
    }

    if (xprv === test_obj[key][2]) {
      console.log("OK");
      return true;
    } else {
      wrong_xprv += key;
      wrong_xprv += " ";
      return true;
    }
  })

  if (wrong_xprv !== "") {
    return "test_hdKeyFromSeed KO: xprv don't match\nwrong key: " + wrong_xprv;
  }
  return "test_hdKeyFromSeed OK: all generated xprv match";
}
