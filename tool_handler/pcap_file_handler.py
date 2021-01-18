from pcapfile import savefile
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii
import re

def get_ips(pkt):
    regex = r"[0-9a-zA-Z\s]* b'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' [0-9a-zA-Z\s]* b'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' [\w\s]*"
    pattern = re.compile(regex)
    matches = re.search(regex,pkt)
    res = [matches.group(1),matches.group(2)] if matches!= None else []
    return res


def read_pcap(path):
    with open(path,"rb") as pcap:
        capfile = savefile.load_savefile(pcap,verbose = True)
        packets = capfile.packets
        eth_frames = [ethernet.Ethernet(pck.raw()) for pck in packets]
        ip_packets = [ip.IP(binascii.unhexlify(frame.payload)) for frame in eth_frames]
        
        #return [{"payload":str(pkt.payload,encoding="utf-8"),"ipv4":str(pkt,encoding="utf-8")} for pkt in ip_packets]
        res = []
        for pkt in ip_packets:
            #print(str(pkt))
            ips = get_ips(str(pkt))
            curr = {}
            curr["payload"] = str(pkt.payload,encoding="utf-8")
            curr["from"] = ips[0]
            curr["to"] = ips[1]
            res.append(curr)

        return res

def count_matches(packets, ips):
    ip_list = list(map(lambda pc: (pc["from"],pc["to"]),packets))
    #print(list(ip_list))
    res = {}
    for ip in ips:
        num = 0
        for fro,to in ip_list:
            if ip == fro or ip == to:
                num+=1
        res[ip] = num
    
    return res
