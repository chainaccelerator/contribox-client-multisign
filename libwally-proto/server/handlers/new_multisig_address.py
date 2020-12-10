import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_multisig_address')
def new_multisig_address(threshold: int, xpubs: str, hd_paths: str) -> dict:
    address, redeem_script = proto.new_multisig_address(threshold, xpubs, hd_paths)
    return {
        "redeem script": redeem_script, 
        "address": address, 
        }
