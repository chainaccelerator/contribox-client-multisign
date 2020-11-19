import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_confidential_address')
def new_confidential_address(chain: str, address: str, master_blinding_key: str) -> str:
    return proto.get_confidential_address_from_addr(chain, address, master_blinding_key)