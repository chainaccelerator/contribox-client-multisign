# crypto-node executable

## Why?

Nodes and users need to be able to exchange encrypted data on our network. This implies the ability to encrypt data with the public key that is known to belong to the intended recipient of our message, and that this recipient will also be able to decrypt it.  
`crypto-node` is a little binary file that can be called by the node server layer, and that implements the same cryptographic functions used on the user wasm module. This makes sure that nodes and users implement exactly the same code and can always encrypt/decrypt messages regardless of who encrypt it for whom.  

## How?

`crypto-node` takes 5 positional arguments:
1. a command: `encrypt` or `decrypt`
2. 32B of entropy in hex form: this is used to initialize libsecp internal PRNG
3. a (compressed) pubkey: this is either the pubkey of the recipient when we encrypt or the ephemeral pubkey provided by the sender along with the encrypted message
4. the message: either a clear text we want to encrypt or the cipher text encoded in base58 to decrypt
5. a private key (which is really 32B of randomness in hex): this is either an ephemeral private key if we encrypt a message or our own private key if we want to decrypt a message sent to us.

The entropy and the ephemeral private key can be obtained by any PRNG available on the server, for example `openssl rand -hex 32`.

## TO-DO
* Compile from the same sources than the wasm module to prevent code duplication
* Add signature feature
* Allow encryption and decryption from a bip32 key
