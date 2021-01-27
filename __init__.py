from flask import Flask
from flask_cors import CORS
import json
from os import path
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
ctx =  app.app_context()
ctx.push()

from api.memorydump_component.volatility_api import volatility_api
from api.memorydump_component.be_api import be_api
from api.memorydump_component.memdump_grep_api import memdump_grep_api
from api.pagefile_component.pagefile_grep_api import pagefile_grep_api

app.register_blueprint(volatility_api, url_prefix = "/volatility") #volatility api
app.register_blueprint(be_api,url_prefix = "/be") #bulk extractor api
app.register_blueprint(memdump_grep_api,url_prefix = "/memdump") #memdump grep api
app.register_blueprint(pagefile_grep_api,url_prefix = "/pagefile") #pagefile grep api

if __name__ == '__main__':
    app.run(debug = True)
