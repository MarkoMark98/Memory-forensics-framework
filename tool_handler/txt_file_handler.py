import re
from collections import Counter
from mmap import mmap
from os import path as pt
try:
    from mmap import PROT_READ as reading_mode
except ImportError:
    from mmap import ACCESS_READ as reading_mode

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
        result[keyword] = int(num)
    
    return result

def find_matching_strings(strings,keyword):

    regex = rf"[^\s]*{keyword}[^\s]*"
    pattern = re.compile(regex,re.IGNORECASE)

    res = {}

    for string in strings:
        matches = re.findall(pattern,string)
        if matches != None:
            for match in matches:
                if res.get(match):
                    res[match] +=1
                else:
                    res[match] = 1
            
    return res



def find_occurrences(path,keywords):
    
    result = {}

    for keyword in keywords:

        regex = rf"n=([0-9]+)\s*([^\s]*{keyword}[^\s]*)"
    
        pattern = re.compile(regex,re.IGNORECASE)

        total = []
        with open(pt.realpath(path),"r") as fh:
            for line in fh:
                
                matches = re.search(regex,line)
                if matches != None:
                    total.append((matches.group(1),matches.group(2)))
        
        result[keyword] = get_occurence_number(total)

    return result


def find_occurrences_alt(path, keywords):
    #return {"test":"to implement"}
    res = {}
    for kw in keywords:
        temp = []
        regex = rf"{kw}"
        pattern = re.compile(regex,re.IGNORECASE)

        with open(path,"r") as fh:
            for line in fh:
                match = re.search(pattern,line)
                if match != None and line[0] != "#":
                    temp.append(line)

        res[kw] = Counter(temp)
        
    return res


def strings(fname, kw, n=6):
    try:
        with open(pt.realpath(fname), 'rb') as f, mmap(f.fileno(), 0, prot=reading_mode) as m:
            for match in re.finditer(('([\w/]{%s}[\w/]*)' % n).encode(), m):
                yield match.group(0)
    except:
        with open(pt.realpath(fname), 'rb') as f, mmap(f.fileno(), 0, access=reading_mode) as m:
            for match in re.finditer(('([\w/]{%s}[\w/]*)' % n).encode(), m):
                yield match.group(0)
            
    

def get_kw_dictionary(keywords,file_path):
    
    temp = []
    words = strings(file_path, keywords)

    for word in words:
        temp.append(str(word,encoding="utf-8"))

    result = {}
    for keyword in keywords:
        result[keyword] = find_matching_strings(temp,keyword)

    return result