import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_address')
def new_address(xpub: str, hd_path: str) -> dict:
    address, pubkey = proto.get_address_from_xpub(xpub, hd_path)
    return {
        "address": address, 
        "pubkey": pubkey, 
        }
