from flask import Flask, Blueprint, current_app ,request
from flask_restful import Api, Resource
import os
import json
from utils import pcap_handler as pcap
from utils import txt_file_handler as tfh

be_api = Blueprint('be_api', __name__,  static_folder="static")

'''
The body of the POST request needs to have this layout
{
    "domain_histogram.txt" : "sample1",
    "email_histogram.txt" : "sample2",
    "email_domain_histogram.txt" : "sample3",
    "ip_histogram.txt" : "sample4",
    "rfc822.txt" : "sample5",
    "url_histogram.txt" : "sample6",
    "url_services.txt" : "sample7"
}
'''
@be_api.route("",methods=["POST"])
def be_search():
    #call to bulk estractor to carve files
    prefix = os.environ.get("BE_OUTPUT_DIR")+"/"
    dump_path = os.environ.get('DUMP_PATH')
    destination = os.environ.get("BE_OUTPUT_DIR")
    command = f"bulk_extractor -o {destination} {dump_path}"
    #os.system(command)

    result = {}
    #Getting keywords from request body
    #the keywords must be equal to teh file names
    keywords = request.json
    
    #gtting key names
    keys = keywords.keys()
    #fills dictionary with
    for key in keys:
        result[key] = tfh.find_occurrences(prefix+key, keywords[key])
    

    packets = pcap.read_pcap(prefix+"packets.pcap")
    
    #result["packets"] = packets

    
    return result