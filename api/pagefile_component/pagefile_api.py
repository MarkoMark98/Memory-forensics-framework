from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
from flask_cors import cross_origin
import os
import json
from tool_handler import txt_file_handler as tfh

pagefile_api = Blueprint('pagefile_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "keywords" : ["sample1", "sample2", ...],
}
'''
@pagefile_api.route("/strings",methods = ["POST"])
@cross_origin()
def pagefile_search():

    keywords = request.json["keywords"]
    dump_path = os.environ.get('PF_PATH')

    return tfh.get_kw_dictionary(keywords,dump_path)
 