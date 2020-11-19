import wallycore as wally
import logging
import json
from os import urandom, path
from struct import pack

import contribox_proto.exceptions as exceptions
from contribox_proto.util import (
    CHAINS,
    PREFIXES,
    CA_PREFIXES,
    KEYS_DIR,
    BLINDING_KEYS_DIR,
    btc2sat,
    save_masterkey_to_disk,
    save_salt_to_disk,
    get_masterkey_from_disk,
    harden,
    bin_to_hex,
    check_dir,
    parse_path,
    hdkey_to_base58,
    tx_input_has_witness,
    reverse_bytes,
    is_json,
    AES_CHAIN,
)

SALT_LEN = 32
HMAC_COST = 2048
NETWORK_LIQUID_REGTEST = 0x04

def generate_entropy_from_password(password):
    """we can generate entropy from some password. A salt is generated randomly and then discarded.
    """
    # Fail if password is None or empty
    if len(password) < 1:
        logging.error("You provided no password")
        raise exceptions.MissingValueError("Can't generate a new seed without password")
    elif len(password) < 16:
        logging.warning(f"Password provided is only {len(password)} characters long\n"
                            "That might be too short to be secure")

    _pass = password.encode('utf-8')
    logging.info(f"Generating salt of {SALT_LEN} bytes")
    salt = bytearray(urandom(SALT_LEN))

    # Let's generate entropy from the provided password
    entropy = bytearray('0'.encode('utf-8') * 64)
    entropy = wally.pbkdf2_hmac_sha512(_pass, salt, 0, HMAC_COST)

    return entropy

def generate_mnemonic_from_entropy(entropy):
    """Generate a mnemonic of either 12 or 24 words.
    We can feed it the entropy we generated from a password or another way.
    We should generate 24 words if we want it to be compatible with Ledger
    """
    if len(entropy) not in [16, 32]:
        raise exceptions.UnexpectedValueError(f"Entropy is {len(entropy)}. "
                                                "It must be 16 or 32 bytes.")
    mnemonic = wally.bip39_mnemonic_from_bytes(None, entropy) # 1st argument is language, default is english
    logging.info(f"mnemonic generated from entropy.")
    logging.debug(f"Mnenonic is {''.join(mnemonic)}")
    return mnemonic

def generate_master_blinding_key_from_seed(seed, chain, fingerprint, dir=KEYS_DIR):
    """Generate the master blinding key from the seed, and save it to disk
    """
    master_blinding_key = bytearray(64)
    master_blinding_key = wally.asset_blinding_key_from_seed(seed) # SLIP-077 derivation

    # Save the blinding key to disk in a separate dir
    save_masterkey_to_disk(chain, master_blinding_key, fingerprint, True, dir)

def generate_seed_from_mnemonic(mnemonic, passphrase=None):
    seed = bytearray(64) # seed is 64 bytes
    wally.bip39_mnemonic_to_seed(mnemonic, passphrase, seed)
    return seed

def get_blinding_key_from_address(address, chain, fingerprint):
    # First retrieve the master blinding key from disk
    masterkey = get_masterkey_from_disk(chain, fingerprint, True)
    # Next we compute the blinding keys for the address
    script_pubkey = wally.addr_segwit_to_bytes(address, PREFIXES.get(chain), 0)
    private_blinding_key = wally.asset_blinding_key_to_ec_private_key(masterkey, script_pubkey)

    return private_blinding_key

def get_master_blinding_key(chain, fingerprint):
    bkey = get_masterkey_from_disk(chain, fingerprint, True)
    return str(bkey.hex())

def generate_masterkey_from_mnemonic(mnemonic, chain, size, passphrase=None, dir=KEYS_DIR):
    """Generate a masterkey pair + a master blinding key if chain is Elements.
    seed is 64B by default but we can also use only the first 32B encoded in WIF
    in case we need to be compatible with Bitcoin Core wallet. 
    """
    if chain in ['bitcoin-main', 'liquidv1']:
        version = wally.BIP32_VER_MAIN_PRIVATE
        wif_prefix = wally.WALLY_ADDRESS_VERSION_WIF_MAINNET
    else:
        version = wally.BIP32_VER_TEST_PRIVATE
        wif_prefix = wally.WALLY_ADDRESS_VERSION_WIF_TESTNET
    
    # first get the seed from the mnemonic.
    seed = generate_seed_from_mnemonic(mnemonic, passphrase)

    # If size is 32, we truncate the seed down to 32B in order to import it in Bitcoin Core
    if size == '32':
        seed = seed[:32]
        wif = wally.wif_from_bytes(seed, wif_prefix, wally.WALLY_WIF_FLAG_COMPRESSED)
        logging.debug(f"Seed in WIF is {wif}")

    # Now let's derivate the master privkey from seed
    masterkey = wally.bip32_key_from_seed(seed, version, 0)
    fingerprint = bytearray(4)
    wally.bip32_key_get_fingerprint(masterkey, fingerprint)

    # dump the hdkey to disk. Create a dir for each chain, filename is key fingerprint
    save_masterkey_to_disk(chain, masterkey, str(fingerprint.hex()), False, dir)

    # If chain is Elements, we can also derive the blinding key from the same seed
    if chain in ['liquidv1', 'elements-regtest']:
        generate_master_blinding_key_from_seed(seed, chain, str(fingerprint.hex()), dir)

    # We return the fingerprint only to the caller and keep the keys here
    return str(bin_to_hex(fingerprint))

def get_pubkey_from_xpub(xpub: str, derivation_path: str):
    lpath = parse_path(derivation_path)
    last = lpath.pop()
    current = wally.bip32_key_from_base58(xpub)
    for path in lpath:
        print(f"current is {current}, path is {path}\n")
        child = wally.bip32_key_from_parent(current, path, wally.BIP32_FLAG_KEY_PUBLIC)
        current = child
    return wally.bip32_key_from_parent(current, last, wally.BIP32_FLAG_KEY_PUBLIC)
    
def get_address_from_xpub(xpub: str, derivation_path: str):
    lpath = parse_path(derivation_path)
    last = lpath.pop()
    current = wally.bip32_key_from_base58(xpub)
    for path in lpath:
        child = wally.bip32_key_from_parent(current, path, wally.BIP32_FLAG_KEY_PUBLIC)
        current = child
    return wally.bip32_key_from_parent(current, last, wally.BIP32_FLAG_KEY_PUBLIC)

def get_child_from_path(chain, fingerprint, derivation_path, dir=KEYS_DIR):
    masterkey = get_masterkey_from_disk(chain, fingerprint, False, dir)
    lpath = parse_path(derivation_path)
    last = lpath.pop()
    current = masterkey
    for path in lpath:
        child = wally.bip32_key_from_parent(current, path, wally.BIP32_FLAG_KEY_PRIVATE)
        current = child
    return wally.bip32_key_from_parent(current, last, wally.BIP32_FLAG_KEY_PRIVATE)

def get_xpub(chain, fingerprint, path, dir=KEYS_DIR):
    if path == 'root':
        masterkey = get_masterkey_from_disk(chain, fingerprint)
    else:
        masterkey = get_child_from_path(chain, fingerprint, path, dir)
    return hdkey_to_base58(masterkey, False)


def get_address_from_path(chain, fingerprint, derivation_path, dir=KEYS_DIR):
    # get the child extended key
    child = get_child_from_path(chain, fingerprint, derivation_path, dir)
    # get a new segwit native address from the child
    address = wally.bip32_key_to_addr_segwit(child, PREFIXES.get(chain), 0)

    # get the pubkey
    pubkey = wally.ec_public_key_from_private_key(wally.bip32_key_get_priv_key(child))
    
    # If Elements, get the blinding key, and create the corresponding confidential address
    if chain in ['liquidv1', 'elements-regtest']:
        blinding_privkey = get_blinding_key_from_address(address, chain, fingerprint)
        blinding_pubkey = wally.ec_public_key_from_private_key(blinding_privkey)
        address = wally.confidential_addr_from_addr_segwit(
                                                            address, 
                                                            PREFIXES.get(chain),
                                                            CA_PREFIXES.get(chain), 
                                                            blinding_pubkey
                                                        )
    else:
        blinding_privkey = None

    return address, pubkey, blinding_privkey

def generate_new_hd_wallet(chain, entropy, is_bytes, size):
    # First make sure we know for which network we need a seed
    try:
        assert chain in CHAINS
    except AssertionError:
        raise exceptions.UnexpectedValueError("Unknown chain.")

    # Check that the ssm-keys dir exists, create it if necessary
    check_dir(KEYS_DIR)

    if is_bytes == True:
        # This can be useful for testing, but it is not recommended for production since the 
        # entropy that is passed in argument is not salted
        mnemonic = generate_mnemonic_from_entropy(bytes.fromhex(entropy))
    else:
        stretched_key = generate_entropy_from_password(entropy)
        mnemonic = generate_mnemonic_from_entropy(stretched_key[:32])
    
    fingerprint = generate_masterkey_from_mnemonic(mnemonic, chain, size)

    xpub = get_xpub(chain, fingerprint, 'root')

    bkey = get_master_blinding_key(chain, fingerprint)

    return fingerprint, xpub, bkey

def restore_hd_wallet(chain, hdkey, bkey=None, dir=KEYS_DIR):
    """
    We need to provide the master blinding key to restore elements wallet.
    If this has not been saved separately, there's no way to retrieve it from the hdkey only.
    Bkey must be hex encoded, and must be 64 bytes long
    """
    # First check the chain we're on
    try:
        assert chain in CHAINS
    except AssertionError:
        raise exceptions.UnexpectedValueError("Unknown chain.")

    # If we are on Elements, check that the blinding key is provided
    if chain in ['liquidv1', 'elements-regtest']:
        try:
            assert int(len(bkey)/2) == 64
        except AssertionError:
            raise exceptions.UnexpectedValueError("A 64B hex string must be provided.")

    # Check that the ssm-keys dir exists, create it if necessary
    check_dir(KEYS_DIR)

    masterkey = wally.bip32_key_from_base58(hdkey)

    fingerprint = bytearray(4)
    wally.bip32_key_get_fingerprint(masterkey, fingerprint)
    save_masterkey_to_disk(chain, masterkey, str(fingerprint.hex()), False, dir)
    # If Elements, save the provided blinding key
    if chain in ['liquidv1', 'elements-regtest']:
        save_masterkey_to_disk(chain, bytes.fromhex(bkey), str(fingerprint.hex()), True, dir)

    return str(fingerprint.hex())

def get_btc_sighash(tx, index, scriptCode, value):
    hashToSign = wally.tx_get_btc_signature_hash(tx, index, 
        scriptCode, 
        value, 
        wally.WALLY_SIGHASH_ALL, 
        wally.WALLY_TX_FLAG_USE_WITNESS)
    return hashToSign

def get_elements_sighash(tx, index, scriptCode, value):
    hashToSign = wally.tx_get_elements_signature_hash(tx, index, 
        scriptCode, 
        value, 
        wally.WALLY_SIGHASH_ALL, 
        wally.WALLY_TX_FLAG_USE_WITNESS)
    return hashToSign

def sign_btc_input(tx, index, privkey, value):
    # we need the value as an int in satoshis
    value = btc2sat(float(value))

    # we need the pubkey to write the ScriptCode that will be signed
    pubkey = wally.ec_public_key_from_private_key(privkey)
    witnessProgram = wally.hash160(pubkey)
    scriptCode = bytearray([0x76, 0xa9, 0x14]) + witnessProgram + bytearray([0x88, 0xac])

    # we can now calculate the signature hash
    hashToSign = get_btc_sighash(tx, index, scriptCode, value)

    # We sign the signature hash with the private key
    sig = wally.ec_sig_from_bytes(privkey, hashToSign, wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)

    # We now return the signature encoded in der format and add the SIGHASH
    return wally.ec_sig_to_der(sig) + bytearray([wally.WALLY_SIGHASH_ALL])

def sign_elements_input(tx, index, privkey, value):
    # we need the blinded value as a bytearray
    try:
        value = bytearray.fromhex(value)
    except ValueError:
        value = btc2sat(float(value))
        value = wally.tx_confidential_value_from_satoshi(value)

    # we need the pubkey to write the ScriptCode that will be signed
    pubkey = wally.ec_public_key_from_private_key(privkey)
    witnessProgram = wally.hash160(pubkey)
    scriptCode = bytearray([0x76, 0xa9, 0x14]) + witnessProgram + bytearray([0x88, 0xac])

    # we can now calculate the signature hash
    hashToSign = get_elements_sighash(tx, index, scriptCode, value)

    # We sign the signature hash with the private key
    sig = wally.ec_sig_from_bytes(privkey, hashToSign, wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)

    # We now return the signature encoded in der format and add the SIGHASH
    return wally.ec_sig_to_der(sig) + bytearray([wally.WALLY_SIGHASH_ALL])

def get_witness_stack(sig, pubkey):
    witnessStack = wally.tx_witness_stack_init(2)
    wally.tx_witness_stack_add(witnessStack, sig)
    wally.tx_witness_stack_add(witnessStack, pubkey)
    return witnessStack

def sign_tx(chain, tx, fingerprints, paths, values, dir=KEYS_DIR):
    """TODO: we can't know if an input is spending a segwit UTXO without access to the UTXO
    to prevent exchanging too much data, we should rely on the client signaling a 
    non-segwit UTXO
    TODO: since we only need `value` for spending segwit output, maybe we could say that
    a value of `0` means the output is a legacy
    TODO: we still can't handle P2SH
    """

    # first extract the fingerprints and paths in lists
    fingerprints = fingerprints.split()
    paths = paths.split()
    values = values.split()

    # Get a tx object from the tx_hex
    if chain in ['bitcoin-main', 'bitcoin-test', 'bitcoin-regtest']: 
        Tx = wally.tx_from_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS) 
    else: 
        Tx = wally.tx_from_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS)

    # Get the number of inputs
    inputs_len = wally.tx_get_num_inputs(Tx)

    # Check if all the lists are of the same length
    try:
        assert inputs_len == len(fingerprints) == len(paths) == len(values)
    except:
        raise exceptions.MissingValueError(f"""
                                            Tx has {inputs_len} inputs, {len(fingerprints)} fingerprints, 
                                            {len(paths)} paths, and {len(values)} values provided. 
                                            Must be the same number.
                                            """)
           
    # Now we loop on each fingerprint provided, compute the sighash and sign the same index input
    for i in range(0, inputs_len):
        # First check if the input already has a witness. If so it means that this input was
        # signed either by us or someone else, and we just skip it
        if tx_input_has_witness(Tx, i) == True:
            continue

        # We derive the child key for the provided fingerprint and path
        child = get_child_from_path(chain, fingerprints[i], paths[i], dir)

        # From here we extract the private key that we will sign with
        privkey = wally.bip32_key_get_priv_key(child)
        pubkey = wally.ec_public_key_from_private_key(privkey)

        # we now sign the input and get the signature and pubkey to populate the witness
        if chain in ['bitcoin-main', 'bitcoin-test', 'bitcoin-regtest']: 
            sig = sign_btc_input(Tx, i, privkey, values[i])
        else: 
            sig = sign_elements_input(Tx, i, privkey, values[i])

        # Create a new witness stack and populate it with sig and pubkey
        witnessStack = get_witness_stack(sig, pubkey)

        # now add the witness stack to the current input
        wally.tx_set_input_witness(Tx, i, witnessStack)

    return wally.tx_to_hex(Tx, wally.WALLY_TX_FLAG_USE_WITNESS) 

def add_script_to_tx(chain, tx, amount, script):
    script_bin = bytes.fromhex(script)

    if chain in ['bitcoin-main', 'bitcoin-test', 'bitcoin-regtest']: 
        Tx = wally.tx_from_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS) 
    else: 
        Tx = wally.tx_from_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS)

    wally.tx_add_raw_output(Tx, int(amount), script_bin, 0)

    return wally.tx_to_hex(Tx, wally.WALLY_TX_FLAG_USE_WITNESS)

def hash_contract(contract):
    if is_json(contract) == True:
        json_dict = json.loads(contract)
        to_hash = json.dumps(json_dict)
    else:
        to_hash = contract
    contract_hash = wally.sha256(to_hash.encode('ascii'))
    reversed_bytes = reverse_bytes(contract_hash)
    return reversed_bytes.hex()

def verify_contract_commitment(chain, txid, vout, contract, asset_id):
    contract_hash = hash_contract(contract)

    reversed_contract_hash = reverse_bytes(bytes.fromhex(contract_hash))

    entropy = wally.tx_elements_issuance_generate_entropy(wally.hex_to_bytes(txid)[::-1], int(vout), reversed_contract_hash)
    asset = wally.tx_elements_issuance_calculate_asset(entropy)[::-1]

    if wally.hex_from_bytes(asset) == asset_id:
        return True

    return False

def new_multisig_address(chain, n, m, xpubs, paths):
    threshold = int(n)
    total_pubkeys = int(m)
    if threshold <= 0 or threshold > total_pubkeys:
        raise exceptions.UnexpectedValueError("threshold must be comprised between 1 and the total number of signers")
    xpubs_list = xpubs.split()
    paths_list = paths.split()
    if len(xpubs_list) != len(paths_list) or len(xpubs_list) != total_pubkeys:
        raise exceptions.UnexpectedValueError("Must provide as many xpubs and paths as signers")

    pubkeys_bin = bytes("", 'ascii')

    # concatenate all the pubkeys in bytes form
    for i in range(total_pubkeys):
        child = get_pubkey_from_xpub(xpubs_list[i], paths_list[i])
        pubkey = wally.bip32_key_get_pub_key(child)
        pubkeys_bin = pubkeys_bin + pubkey

    # generate the scriptpubkey
    redeem_script = wally.scriptpubkey_multisig_from_bytes(pubkeys_bin, int(threshold), 0)
    script_hash = wally.sha256(redeem_script)
    script_pubkey = bytearray([0x0, 0x20]) + script_hash

    address = wally.addr_segwit_from_bytes(script_pubkey, PREFIXES.get(chain), 0)
    return address, wally.hex_from_bytes(redeem_script)

def new_tx_with_output(chain, amount, asset, script):
    if '.' in amount:
        raise exceptions.UnexpectedValueError("amount must be in satoshis.")
    
    try:
        script_bin = wally.hex_to_bytes(script)
    except ValueError:
        raise exceptions.UnexpectedValueError("Script is not a valid hexstring")
    
    try:
        asset_bin = wally.hex_to_bytes(asset)
    except ValueError:
        raise exceptions.UnexpectedValueError("Provided asset ID is not an hexstring")
    if len(asset_bin) is not 32:
        raise exceptions.UnexpectedValueError("asset ID must be 32B long.")
    
    value = wally.tx_confidential_value_from_satoshi(int(amount))
    fee_value = wally.tx_confidential_value_from_satoshi(0)

    new_tx = wally.tx_init(2, 0, 0, 0)

    output = wally.tx_elements_output_init(
        script_bin, 
        bytearray([0x01]) + asset_bin, 
        value,
        None, 
        None, 
        None)

    fee_output = wally.tx_elements_output_init(
        None, 
        bytearray([0x01]) + asset_bin, 
        fee_value,
        None, 
        None, 
        None)

    wally.tx_add_output(new_tx, output)
    wally.tx_add_output(new_tx, fee_output)
    
   # wally.tx_add_elements_raw_output(
   #     new_tx, 
   #     script_bin, 
   #     bytearray([0x01]) + asset_bin, 
   #     value, 
   #     None, 
   #     None, 
   #     None, 
   #     0)

    return new_tx 

def update_tx_with_input(chain, enrollment_tx, utxo):
    if len(utxo.split(':')) != 2:
        raise exceptions.UnexpectedValueError("utxo must be in txid:vout format")
    prev_id, prev_out = utxo.split(':')

    try:
        prev_id_bin = wally.hex_to_bytes(prev_id)
    except ValueError:
        raise exceptions.UnexpectedValueError("Provided tx ID is not an hexstring")
    if len(prev_id_bin) is not 32:
        raise exceptions.UnexpectedValueError("tx ID must be 32B long.")

    if '.' in prev_out or int(prev_out) < 0:
        raise exceptions.UnexpectedValueError("prev_out must be a positive integer")
    
    wally.tx_add_elements_raw_input(
        enrollment_tx,
        prev_id_bin,
        int(prev_out),
        0xffffffff,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        0)

    return wally.tx_to_hex(enrollment_tx, wally.WALLY_TX_FLAG_USE_WITNESS)

def start_aes_session(pubkey):
    # verify that the pubkey is valid for secp256k1
    #if not wally.ec_public_key_verify(pubkey_bin):
    #    raise exceptions.UnexpectedValueError("pubkey is not on the secp256k1 curve")

    # we generate a random key pair
    ephemeral_privkey = urandom(32) # random, but could also derive it determinastically from a secret and their pubkey
    ephemeral_pubkey = wally.ec_public_key_from_private_key(ephemeral_privkey)

    # we generate a new session id
    # it's random now, but it could be useful to derive it determinastically from the pubkey
    session_id = int.from_bytes(urandom(2), "little")

    # get a shared_key from ECDH
    shared_key = wally.ecdh(wally.hex_to_bytes(pubkey), ephemeral_privkey)

    # create AES key using derivation
    # using pbkdf here is a bit of an overkill, hbkd would be enough, but we don't have it in libwally
    # I don't know if we need to bother with a salt here
    derived_key = '\x00'*32
    derived_key = wally.pbkdf2_hmac_sha256(shared_key, b'', 0, 1024)

    # we save the key on disk with the session_id
    save_masterkey_to_disk(AES_CHAIN, derived_key, str(session_id))

    # return a pubkey and a session_id for later communication
    return ephemeral_pubkey.hex(), session_id

def encrypt_msg_for_session(msg, session_id):
    # we check that the session_id is known and that we have a key
    session_key = get_masterkey_from_disk(AES_CHAIN, str(session_id))
    # the problem here is to get reliable random number for AES iv. 
    # I'll use urandom here, but I won't be able to rely on it on production
    aes_iv = urandom(16)

    # encrypt msg with AES
    clear_text = msg.encode('utf-8')
    cipher_len = len(clear_text)//16*16+16
    print(f"cipher_len is {cipher_len}")
    cipher = bytearray(cipher_len)
    wally.aes_cbc(session_key, aes_iv, clear_text, wally.AES_FLAG_ENCRYPT, cipher)

    # return encrypted msg and iv
    return wally.base58_from_bytes(cipher, wally.BASE58_FLAG_CHECKSUM), wally.base58_from_bytes(aes_iv, wally.BASE58_FLAG_CHECKSUM)

def decrypt_msg_for_session(msg, session_id, iv):
    # we check that the session_id is known and that we have a key
    session_key = get_masterkey_from_disk(AES_CHAIN, str(session_id))

    aes_iv = wally.base58_to_bytes(iv, wally.BASE58_FLAG_CHECKSUM)

    # decrypt msg with AES
    cipher = wally.base58_to_bytes(msg, wally.BASE58_FLAG_CHECKSUM)
    clear_len = len(cipher)//16*16
    print(f"clear_len is {clear_len}")
    clear_text = bytearray(clear_len)
    wally.aes_cbc(session_key, aes_iv, cipher, wally.AES_FLAG_DECRYPT, clear_text)

    # return decrypted msg
    return clear_text.decode('utf-8')

def get_address_from_xpub(chain, xpub, path):
    # derive the hdkey from the xpub
    child = get_pubkey_from_xpub(xpub, path)

    # get the pubkey
    pubkey = wally.bip32_key_get_pub_key(child)

    # get the bech32 address
    address = wally.bip32_key_to_addr_segwit(child, PREFIXES.get(chain), 0)

    return address, str(pubkey.hex())

def get_confidential_address_from_addr(chain, address, master_blinding_key):
    # derive the blinding key pairs
    masterkey = bytes.fromhex(master_blinding_key)
    script_pubkey = wally.addr_segwit_to_bytes(address, PREFIXES.get(chain), 0)
    private_blinding_key = wally.asset_blinding_key_to_ec_private_key(masterkey, script_pubkey)
    blinding_pubkey = wally.ec_public_key_from_private_key(private_blinding_key)

    # create a confidential address 
    return wally.confidential_addr_from_addr_segwit(address, 
                                                    PREFIXES.get(chain),
                                                    CA_PREFIXES.get(chain), 
                                                    blinding_pubkey
                                                    )
