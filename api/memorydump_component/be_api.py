from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
import os
from os import path
import json
from tool_handler import pcap_file_handler as pcap
from tool_handler import txt_file_handler as tfh

names = set([
    "domain_histogram.txt",
    "email_histogram.txt" ,
    "email_domain_histogram.txt" ,
    "ip_histogram.txt" ,
    "url_histogram.txt",
    "url_services.txt"
    ]
    )

be_api = Blueprint('be_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "domain_histogram.txt" : ["sample2",...],
    "email_histogram.txt" : ["sample3",...],
    "email_domain_histogram.txt" : ["sample4",...],
    "ip_histogram.txt" : ["sample5",...],
    "rfc822.txt" : ["sample6",...],
    "url_histogram.txt" : ["sample7",...],
    "url_services.txt" : ["sample8",...]
}
'''
@be_api.route("",methods=["POST"])
def be_search():
    #call to bulk estractor to carve files
    prefix = path.realpath(os.environ.get("BE_OUTPUT_DIR"))+"/"
    dump_path = path.realpath(os.environ.get('DUMP_PATH'))
    destination = path.realpath(os.environ.get("BE_OUTPUT_DIR"))
    command = f"bulk_extractor -o \"{destination}\" \"{dump_path}\""
    #os.system(command)

    #result dictionary
    result = {}

    #Getting keywords from request body
    #the keywords must be equal to teh file names
    keywords = request.json
    
    #gtting key names
    keys = keywords.keys()
    #fills dictionary with
    for key in keys:
        if key in names:
            result[key] = tfh.find_occurrences(prefix+key, keywords[key])
        else:
            result[key] = tfh.find_occurrences_alt(prefix+key, keywords[key])
    
    return result

'''
The body of the POST request needs to have this layout
{
    "keywords" : ["sample1", "sample2", ...],
}
'''
@be_api.route("/strings",methods=["POST"])
def memdump_search():

    keywords = request.json["keywords"]
    dump_path = os.environ.get('DUMP_PATH')

    return tfh.get_kw_dictionary(keywords,dump_path)


@be_api.route("/pcap",methods=["GET"])
def be_packets():
    prefix = os.environ.get("BE_OUTPUT_DIR")+"/"
    #dealing with packets
    packets = pcap.read_pcap(prefix+"packets.pcap")
    return {"packets" : packets}
