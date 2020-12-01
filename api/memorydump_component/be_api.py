from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
import os
import json

be_api = Blueprint('be_api', __name__,  static_folder="static")

@be_api.route("",methods=["POST"])
def be_search():
    #call to bulk estractor to carve files
    os.system("bulk_extractor -o ../../be_results "+current_app.config['dump_path'])

    #Getting keywords from request body
    dt = request.json
    
    return dt