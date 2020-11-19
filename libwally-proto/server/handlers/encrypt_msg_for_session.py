import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('encrypt_msg_for_session')
def encrypt_msg_for_session(msg: str, session_id: str)->dict:
    cipher, iv = proto.encrypt_msg_for_session(msg, session_id)

    return {
        "cipher": cipher,
        "initialization vector": iv,
    }
