function test_newWallet() {
  let wallet;

  // password must be a string
  if (wallet = newWallet(1) != "") {
    throw "newWallet KO: must take only strings as input, not number"
  };

  let password = new Uint8Array(12);
  window.Crypto.getRandomValues(password);
  if (wallet = newWallet(password) != "") {
    throw "newWallet KO: must take only strings as input, not array"
  };

  // test the different components of the output
  // we'll need to decrypt the output, and restore the wallet from the seed for that
  return "newWallet OK";
}
