import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('sign_tx')
def sign_tx(chain: str, tx: str, fingerprints: str, paths: str, values: str) -> dict:
    signed_tx = proto.sign_tx(chain, tx, fingerprints, paths, values)
    return {'chain': chain, "signed_tx": signed_tx}
