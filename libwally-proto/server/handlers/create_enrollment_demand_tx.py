import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('create_enrollment_demand_tx')
def create_enrollment_demand_tx(chain: str, prev_tx, my_asset, template_address, my_address, contract_hash)->str:
    return proto.create_tx(chain, prev_tx, my_asset, template_address, my_address, contract_hash)
