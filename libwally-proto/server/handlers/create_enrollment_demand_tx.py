import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('create_enrollment_demand_tx')
def create_enrollment_demand_tx(chain: str, utxo, asset, amount, script):
    address, redeem_script = proto.new_tx_with_output(chain, utxo, asset, amount, script)
    return {
        "chain": chain, 
        "address": address, 
        "redeem script": redeem_script, 
        }
