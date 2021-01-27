from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
from flask_cors import cross_origin
import os
from os import path
import json
from tool_handler import pcap_file_handler as pcap
from tool_handler import txt_file_handler as tfh

memdump_grep_api = Blueprint('memdump_grep_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "keywords" : ["sample1", "sample2", ...],
}
'''
@memdump_grep_api.route("/grep",methods=["POST"])
def memdump_search(): 

    keywords = request.json["keywords"]
    dump_path = os.environ.get('DUMP_PATH')

    return tfh.get_kw_dictionary(keywords,dump_path)