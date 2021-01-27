from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
from flask_cors import cross_origin
import os
import json
from tool_handler import txt_file_handler as tfh

pagefile_grep_api = Blueprint('pagefile_grep_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "keywords" : ["sample1", "sample2", ...],
}
'''
@pagefile_grep_api.route("/grep",methods = ["POST"])
@cross_origin()
def pagefile_search():

    keywords = request.json["keywords"]
    pagefile_path = os.environ.get('PF_PATH')

    return tfh.get_kw_dictionary(keywords, pagefile_path)
 