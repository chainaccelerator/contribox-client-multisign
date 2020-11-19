NLOCKTIME = 0
IS_REPLACEABLE = False
ADDRESS_TYPE = None # Use the default for the wallet

# Use a p2sh-segwit (current liquid default) confidential dummy address so that
# fundrawtransaction allocates the right fees.
DUMMY_ADDRESS = {
    # regtest: wally.base58check_from_bytes(b'\x4b' + b'\x00'*20),
    False: 'XBMEr9McFXkiLWTVqTyuNQR1CqKkMPMn6L',
    # mainnet: wally.base58check_from_bytes(b'\x27' + b'\x00'*20),
    True: 'GhBXQEdEh35AtuSNxMzRutcgYg3nkvq5Wb',
}
# A bech32 dummy address in case we want to use bech32
# dummy_program = b'\x00' + b'\x14' + b'\x00'*20
DUMMY_ADDRESS_BECH32 = {
    # regtest: wally.addr_segwit_from_bytes(dummy_program, 'ert', 0),
    False: 'ert1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4zf532',
    # mainnet: wally.addr_segwit_from_bytes(dummy_program, 'ex', 0),
    True: 'ex1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0srvws',
}
# dummy_pubkey = b'\x02'*33
DUMMY_ADDRESS_CONFIDENTIAL = {
    # regtest: wally.confidential_addr_from_addr(dummy_add, 0x04, dummy_pubkey)
    False: 'Azpj2QQw8ZGASK99L4BVKvH2xW9jerD9QrLenKUML7sQXMqJKJyYSwp99dASLbF5aR'
           'qXifmnTFhVzbZn',
    # mainnet: wally.confidential_addr_from_addr(dummy_add, 0x0c, dummy_pubkey)
    True: 'VJL5bwudesLgrLxF4SPVyxvoWrDJhBpKf9YxQgVpMzfuLDSGndbWS832vZmKoV5KhrC'
          '2RC4SKzvn2ZbE',
}
DUMMY_ADDRESS_CONFIDENTIAL_BLECH32 = {
    # regtest: wally.confidential_addr_from_addr_segwit(dummy_add, 'ert', 'el', dummy_pubkey)
    False: 'el1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqqqqqqqq'
           'qqqqqqqqqqqqqqqqqqqqqqq770cpn3jrz4f',
    # mainnet: wally.confidential_addr_from_addr_segwit(dummy_add, 'ex', 'lq', dummy_pubkey)
    True: 'lq1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqqqqqqqqqq'
          'qqqqqqqqqqqqqqqqqqqqqq4k0tza0zysfn',
}
# FIXME: if the receiver wallet set another addresstype, then this choice may
#        lead to an incorrect fee estimation. In addition, for better anonimity
#        it would be better if all the address types are equal.
