import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('unblind_tx_outputs')
def unblind_tx_outputs(chain: str, prev_tx:str)->dict:
    asset_generators, clear_asset_ids, clear_values, abfs, vbfs, script_pubkeys, vouts = proto.unblind_tx_outputs(chain, prev_tx)

    answer = dict()

    if len(vouts) == 0:
        answer['vouts'] = "no output is ours in this transaction"

    else:
        answer["asset_generators"] = [ag.hex() for ag in asset_generators]
        answer["clear_asset_ids"] = [ca.hex() for ca in clear_asset_ids]
        answer["clear_values"] = clear_values
        answer["abfs"] = [a.hex() for a in abfs]
        answer["vbfs"] = [v.hex() for v in vbfs]
        answer["script_pubkeys"] = [sp.hex() for sp in script_pubkeys]
        answer["vouts"] = vouts

    return answer
