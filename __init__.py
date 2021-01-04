from flask import Flask
import json
from os import path
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
ctx =  app.app_context()
ctx.push()

from api.memorydump_component.volatility_api import volatility_api
from api.memorydump_component.be_api import be_api
from api.pagefile_component.pb_api import pb_api

app.register_blueprint(volatility_api, url_prefix = "/volatility")
app.register_blueprint(be_api,url_prefix = "/be")
app.register_blueprint(pb_api,url_prefix = "/pb")

if __name__ == '__main__':
    app.run(debug = True)

    
