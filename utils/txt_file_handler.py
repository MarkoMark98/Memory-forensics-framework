import re
from collections import Counter

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