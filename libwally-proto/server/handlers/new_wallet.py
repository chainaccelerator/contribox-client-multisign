import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('new_wallet')
def new_wallet(entropy: str) -> dict:
  xpub, xprv, master_blinding_key, seed_phrase = proto.generate_new_hd_wallet(entropy)
  return {'xpub': xpub, 'xprv': xprv, 'master_blinding_key': master_blinding_key, 'seed_phrase': seed_phrase}
