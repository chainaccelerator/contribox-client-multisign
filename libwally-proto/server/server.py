from flask import Flask
import api

app = Flask(__name__)
api.jsonrpc(app, '/api/v1')

# register handlers
import handlers

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=False)
