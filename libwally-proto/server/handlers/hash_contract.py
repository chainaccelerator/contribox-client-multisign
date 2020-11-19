import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('hash_contract')
def hash_contract(chain: str, contract: str) -> str:
    return proto.hash_contract(contract)
