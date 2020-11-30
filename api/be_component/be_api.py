from flask import Flask, Blueprint, current_app
from flask_restful import Api, Resource
import os

be_api = Blueprint('be_api', __name__,  static_folder="static")

@be_api.route("/<keyword>")
def be_search(keyword):
    #call to bulk estractor to carve files
    #os.system("bulk_extractor -o outDir ../../memdump.zip")
    
    return keyword