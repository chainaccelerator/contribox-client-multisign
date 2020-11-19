import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('start_aes_session')
def start_aes_session(pubkey: str)->dict:
    ephemeral_pubkey, session_id = proto.start_aes_session(pubkey)
    return {
        "ephemeral_pubkey": ephemeral_pubkey,
        "session_id": session_id,
    }
