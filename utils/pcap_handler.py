from pcapfile import savefile
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii

def read_pcap(path):
    with open(path,"rb") as pcap:
        capfile = savefile.load_savefile(pcap,verbose = True)
        packets = capfile.packets
        eth_frames = [ethernet.Ethernet(pck.raw()) for pck in packets]
        ip_packets = [ip.IP(binascii.unhexlify(frame.payload)) for frame in eth_frames]
        
        return [{"payload":str(pkt.payload),"ipv4":str(pkt)} for pkt in ip_packets]
    
