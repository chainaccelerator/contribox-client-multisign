# contribox-client-multisign
Web RPC protocol for multisign with Elements transations

## Contribox web plugin

### Architecture

This plugin is composed of 3 parts:
1. Libwally
2. Minsc
3. A middle layer that will expose functional API and calls the low-level libraries

### Libwally

[Libwally](https://github.com/ElementsProject/libwally-core) is a cross-platform library of bitcoin and elements wallet primitives.

It is written in C, and can be compiled with Python or Java wrapper.

See the [API](https://wally.readthedocs.io/) documentation for more information. 

### Minsc 

[Minsc](https://github.com/shesek/minsc) is a scripting language based on [miniscript](http://bitcoin.sipa.be/miniscript/), that can compile to [bitcoin scripts](https://en.bitcoin.it/wiki/Script).  

Scripts are notoriously difficult to write and reason about, and miniscript is a subset of bitcoin script that is designed to be easy to analyze. Every valid miniscript can compile to a valid bitcoin script, but the reverse is not true, bitcoin scripts that use op_codes outside of what's included in miniscript can't be expressed by miniscripts.

That means that while we can't do as many things with miniscript than what could be done with scripts, we can make with miniscript pretty much everything that is actually useful in bitcoin scripts:
* require one or multiple signatures (of course)
* require the preimage of a hash
* require either absolute or relative timelocks

We're using Minsc as an executable on the nodes side for now. We use it to generate bitcoin scripts out of a template written in minsc language. Given a minsc file with all the xpubs and index to populate the script, minsc can take care of address generation and then script generation for us.

The generation of blinding keys must still be done with Libwally. 

### usage of Minsc

1. enrollment:
* the user wanting to enroll must provide his enrollment form, that indicates the organisation he is enrolling to, and his own xpub he got from `getXpub`.
* the node can pick up the right template for the organisation (wich is basically a minsc script), copy it and add user's xpub at a predefined place.
* the node then feed the file to `minsc` executable, that returns the corresponding bitcoin script in hex format. 
* the organisation user that creates enrollment transaction pick up the script from the node.
* at the end the enrolled user must also get a copy of the template that has been used to enroll him. 

2. new contribution/outboarding:
* the contributing user send the template he received when he enrolled to a node
* the node can directly use the template to generate a script by feeding it to `minsc`, and send it back to the user.
* the user can now generate Tx0 with the right script.

## API call

## init

### Inputs

1. None

### Outputs

1. number `success`: if `0`, libwally is ready to go, any other value means something went wrong and none other calls can be made.

## newWallet

### Inputs

1. string `userPassword`: password chosen by the user. 

### Outputs

1. string `encryptedWallet`: a base58 encoded string that contains the following data encrypted with AES:
    * `xprv`: the private extended key.
    * `mnemonic` (or seed words): 12 (or 24) words that allow user to restore his wallet, including the private keys and blinding keys.
    * `masterBlindingKey`: the 64B key used to blind and unblind user's transactions.

### Description

`newWallet` is the first API call that must be made, since it generates all the cryptographic material we need for the subsequent steps.

It generates a seed (a `mnemonic` is basically a human-readable version of this), and from this seed an extended private key. 

From this key it is possible to derivate a virtually unlimited number of new key pairs. 

`xprv` is the most critical piece of information here, as anyone that get a hold of it can impersonate the user in any transaction, not only past, but also to come.

`master_blinding_key` should be protected, as compromising it wouldn't be as bad as the `xprv`, but would allow the attacker to unblind all the users' output.

It uses `userPassword` to encrypt the wallet data (AES CBC), and returns the cipher encoded in a base 58 string.

The same `userPassword` must be provided everytime we need to interact with the wallet. Failure to provide this password could result on the loss of the wallet. That's why users should write down their seed words on a piece of paper so that they can restore their wallet either if the encrypted file is lost or if they forget their password. 

## restoreWallet

### Inputs 

1. string `userPassword`: password chosen by user. It can be different than the one used at wallet generation. 
2. string `mnemonic`: seed words of the wallet that need to be restored. It was either written down at wallet generation or later with `getMnemonic`. 

### Outputs

1. string `encryptedWallet`: the same wallet than `newWallet` return value. The actual string must be different even if we restore with the same `userPassword` since we're using a different initialisation vector each time.  

## newConfidentialAddressFromXpub

### Inputs

1. string `xpub`: our xpub from `getXpub`
2. string `hdPath`: a hierarchical deterministic path for derivation with the provided `xpub`, in the form `"0h/0/1"`. _Note_: `h` stands for "hardened", and can be replace by `'`. 
3. string `encryptedWallet`: return by `new_wallet`. 
4. string `userPassword`

### Outputs

1. string `confidentialAddress`: the blech32 confidential address for the given `address` and `masterBlindingKey`. Is basically `unconfidentialAddress` + `blindingPubkey`.
2. string `blindingPrivkey`: the private key generated (32B) in hex format. Anyone having this information is also able to unblind all the outputs using this address.
3. string `unconfidentialAddress`: the bech32 address for the given `script`.

### Notes
This allow us to create addresses for output that we pay to ourself. For multisig output, we need to obtain a script from the network first, and call `newConfidentialAddressFromScript`.
It would be possible to use the same call and obtain an address from a xpub that doesn't belong to us, BUT it would be blinded with our `masterBlindingKey`,
which is an issue. Giving `unconfidentialAddress` to the owner of the xpub would allow him to blind it using his own keys though, but we probably don't need it.

## newConfidentialAddressFromScript

### Inputs

1. string `script`: returned by minsc.
2. string `encryptedWallet`: return by `new_wallet`. 
3. string `userPassword`

### Outputs

1. string `confidentialAddress`: the blech32 confidential address for the given `address` and `masterBlindingKey`. Is basically `unconfidentialAddress` + `blindingPubkey`.
2. string `blindingPrivkey`: the private key generated (32B) in hex format. Anyone having this information is also able to unblind all the outputs using this address.
3. string `unconfidentialAddress`: the bech32 address for the given `script`.

## create_tx

### Inputs

1. string `prev_tx`: hex encoded transaction containing the UTXO we're spending.
2. string `asset`: hex encoded asset ID of the asset provided on enrollment.
3. string `address_1`: address of the first output.
4. (optional)string `address_2`: address for the second output. 
5. (optional)string `contract_hash`: an optional 32B piece of information (usually, a hash) that can be committed inside the asset issuance.

### Outputs

1. string `tx`: hex encoded new transaction that spends `prev_tx`

## sign_tx

### Inputs

1. string `tx`: hex encoded transaction to sign
2. string `hd_path`: must only contains numeric characters and `/` to separate them. List of indexes used for key derivation. 
3. string `value`: amount of the UTXO we're speding. If the previous transaction was blinded, it is the field `valuecommitment` in the output of `decoderawtransaction` elements rpc call. If it's not, pass the clear amount (e.g. "1.00012").

### Outputs

1. string `signed_tx`: hex encoded signed transaction

## getXpub

### Inputs

1. string `encryptedWallet`: return of `newWallet`.
2. string `password`: password used for creating `encryptedWallet`.

### Outputs

1. string `xpub`: the extended master pubkey, can be used by the user or other users to generate pubkeys that belong to the user.

### Notes 

`xpub` is relatively not critical data, having it would allow an attacker to derive all the pubkeys (hence the address) of the user. This could be a privacy issue, but since we blind everything and use a lot of multisig (which hides the participants pubkey as long as it is not spent), I don't think this is a concern here. 

## getMnemonic

### Inputs

1. string `encryptedWallet`: return of `newWallet`.
2. string `password`: password used for creating `encryptedWallet`.

### Outputs

1. string `mnemonic`: the seed words used to restore the wallet in case the `encryptedWallet` is lost.

### Notes

`mnemonic` is highly sensitive information, and must be shown to user and immediately erased from memory. It must not be saved on disk.
