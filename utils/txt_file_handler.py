import re
from mmap import mmap, PROT_READ

def get_occurence_number(matches):
    '''
    unique_matches = set(matches)
    for el in unique_matches:
        result[el] = matches.count(el)
    '''
    if len(matches) == 0:
        return {}

    result = {}
    for num, keyword in matches:
        result[keyword] = num
    
    return result
    

def find_occurrences(path,keywords):
    
    result = {}

    for keyword in keywords:

        regex = rf"n=([0-9]+)\s*([^\s]*{keyword}[^\s]*)"
    
        pattern = re.compile(regex)

        total = []
        with open(path,"r") as fh:
            for line in fh:
                
                matches = re.search(regex,line)
                if matches != None:
                    total.append((matches.group(1),matches.group(2)))
        
        result[keyword] = get_occurence_number(total)

    return result


def strings(fname, keyword):
        with open(fname, 'rb') as f, mmap(f.fileno(), 0, prot=PROT_READ) as m:
            for match in re.finditer((rf"([^\s]*{keyword}[^\s]*)").encode(), m):
                yield match.group(0)
    
    
