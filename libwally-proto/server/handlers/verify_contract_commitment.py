import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('verify_contract_commitment')
def verify_contract_commitment(chain: str, txid: str, vout: str, contract: str, asset_id: str) -> bool:
    return proto.verify_contract_commitment(chain, txid, vout, contract, asset_id)
