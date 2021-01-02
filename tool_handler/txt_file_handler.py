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

def find_matching_strings(strings,keyword):

    regex = rf"[^\s]*{keyword}[^\s]*"
    pattern = re.compile(regex)

    res = []

    for string in strings:
        matches = re.findall(pattern,string)
        if matches != None:
            res = res + matches
            
    return res



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



def strings(fname, n=6):
    with open(fname, 'rb') as f, mmap(f.fileno(), 0, prot=PROT_READ) as m:
        for match in re.finditer(('([\w/]{%s}[\w/]*)' % n).encode(), m):
            yield match.group(0)
    
    

def get_kw_dictionary(keywords,file_path):
    
    temp = []
    words = strings(file_path)

    for word in words:
        temp.append(str(word,encoding="utf-8"))

    result = {}
    for keyword in keywords:
        result[keyword] = find_matching_strings(temp,keyword)

    return result