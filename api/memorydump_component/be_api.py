from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
import os
import json

be_api = Blueprint('be_api', __name__,  static_folder="static")

@be_api.route("",methods=["POST"])
def be_search():
    #call to bulk estractor to carve files
    dump_path = os.environ.get('DUMP_PATH')
    destination = os.environ.get("OUTPUT_DIR")
    command = f"bulk_extractor -o {destination} {dump_path}"
    #os.system(command)

    #Getting keywords from request body
    dt = request.json
    
    return dt