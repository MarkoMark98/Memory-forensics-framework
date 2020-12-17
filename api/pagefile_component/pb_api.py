from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
import os
import json
from utils import txt_file_handler as tfh

pb_api = Blueprint('pb_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "keywords" : ["sample1", "sample2", ...],
}
'''
@pb_api.route("/strings",methods = ["POST"])
def pagefile_search():

    keywords = request.json["keywords"]
    dump_path = os.environ.get('PF_PATH')

    return tfh.get_kw_dictionary(keywords,dump_path)
