from flask import Flask
import json
from os import path

app = Flask(__name__)
ctx =  app.app_context()
ctx.push()

from memorydump_component.volatility_api import volatility_api
from memorydump_component.be_api import be_api

app.config['dump_path'] = path.realpath(r'C:/Users/Mark/Documents/SharedFolder/dumps/2gb/memdump.mem')

app.register_blueprint(volatility_api, url_prefix = "/volatility")
app.register_blueprint(be_api,url_prefix = "/be")

if __name__ == '__main__':
    app.run(debug = True)