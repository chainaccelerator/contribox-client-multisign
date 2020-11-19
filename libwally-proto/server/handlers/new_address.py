import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_address')
def new_address(chain: str, xpub: str, path: str) -> dict:
    address, pubkey = proto.get_address_from_xpub(chain, xpub, path)
    return {
        "chain": chain, 
        "address": address, 
        "pubkey": pubkey, 
        }
