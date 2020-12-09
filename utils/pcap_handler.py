from pcapfile import savefile

def read_pcap(path):
    with open(path,"rb") as pcap:
        capfile = savefile.load_savefile(pcap,verbose = True)
        return capfile.packets
    
