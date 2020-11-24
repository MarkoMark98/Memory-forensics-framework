from flask import Flask
import json
from os import path

app = Flask(__name__)
ctx =  app.app_context()
ctx.push()

from memorydump_component.volatility_api import volatility_api

app.register_blueprint(volatility_api, url_prefix = "/volatility")

if __name__ == '__main__':
    app.run(host = '10.0.2.15')
