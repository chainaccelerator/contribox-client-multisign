import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('decrypt_msg_for_session')
def decrypt_msg_for_session(msg: str, session_id: str, iv: str)->str:
    return proto.decrypt_msg_for_session(msg, session_id, iv)
