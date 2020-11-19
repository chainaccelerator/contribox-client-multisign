import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_master')
def new_master(chain: str, entropy: str, isbytes: bool, size="64") -> dict:
  fingerprint, xpub, master_blinding_key = proto.generate_new_hd_wallet(chain, entropy, isbytes, size)
  return {'chain': chain, 'fingerprint': fingerprint, 'xpub': xpub, 'master blinding key': master_blinding_key}
