import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_multisig_address')
def new_multisig_address(chain: str, threshold: int, total_signers: int, xpubs: str, paths: str) -> dict:
    address, redeem_script = proto.new_multisig_address(chain, threshold, total_signers, xpubs, paths)
    return {
        "chain": chain, 
        "address": address, 
        "redeem script": redeem_script, 
        }
