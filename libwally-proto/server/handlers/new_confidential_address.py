import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_confidential_address')
def new_confidential_address(address: str, master_blinding_key: str) -> dict:
    confidential_address, private_blinding_key = proto.get_confidential_address_from_addr(address, master_blinding_key)

    return {
        "confidential_address": confidential_address,
        "private_blinding_key": private_blinding_key.hex(),
    }