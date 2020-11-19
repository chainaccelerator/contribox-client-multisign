from flask_jsonrpc import JSONRPC

g_api = None

def jsonrpc(app=None, endpoint=None):
  global g_api

  # initialize global api instance
  if not g_api:
    g_api = JSONRPC(app, endpoint, enable_web_browsable_api=False)

  return g_api
