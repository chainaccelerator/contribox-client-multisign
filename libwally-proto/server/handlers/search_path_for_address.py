import api
import contribox_proto.core as proto

jsonrpc = api.jsonrpc()

@jsonrpc.method('search_path_for_address')
def search_path_for_address(chain:str, xpub:str, target:str, path:str, index:str, range:str)->dict :
    path = proto.search_path_for_address(chain, xpub, target, path, index, range)

    return {
        "path": path,
    }
