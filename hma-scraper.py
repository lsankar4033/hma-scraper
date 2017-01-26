#!/usr/bin/env python

from pymongo import MongoClient

import requests
import re
import sys

MONGO_URI = 'mongodb://localhost:27017/'
MONGO_DB = 'hma_proxies'

def scrape_hma(uri, db):
    r = requests.get('http://proxylist.hidemyass.com/'+uri)
    bad_class='('
    for line in r.text.splitlines():
        class_name = re.search(r'\.([a-zA-Z0-9_\-]{4})\{display:none\}', line)
        if class_name is not None:
            bad_class += class_name.group(1)+'|'
    bad_class = bad_class.rstrip('|')
    bad_class += ')'

    # Remove invisible IP numbers
    to_remove = '(<span class\="' + bad_class + '">[0-9]{1,3}</span>|<span style=\"display:(none|inline)\">[0-9]{1,3}</span>|<div style="display:none">[0-9]{1,3}</div>|<span class="[a-zA-Z0-9_\-]{1,4}">|</?span>|<span style="display: inline">)'

    junk = re.compile(to_remove, flags=re.M) # flag indicating multi-line text
    junk = junk.sub('', r.text)
    junk = junk.replace("\n", "")

    proxy_src = re.findall('([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*</td>\s*' +
                           '<td>\s*([0-9]{2,6}).{100,1200}(socks4/5|HTTPS?)\s*</td>\s*' +
                           '<td nowrap>\s*(Low|Medium|None|High)', junk)

    for src in proxy_src:
        (ip, port, proto, anonymity) = src[:4]
        proto = 'socks5h' if proto == 'socks4/5' else proto.lower() # socks4/5 -> socks5h
        port = int(port)

        if anonymity == 'High': # Only store high anonymity proxies
            db.proxies.update_one({'ip': ip,
                                   'port': port},
                                  {'$set':
                                   {'anonymity': anonymity,
                                    'protocol': proto}},
                                  upsert = True)

if __name__ == '__main__':
    error = 'Input the number of pages to scrape. Ex:\npython hma-scraper.py 30'
    db_client = MongoClient(MONGO_URI)
    try:
        if sys.argv[1].isdigit() == True:
            num_pages = int(sys.argv[1])
            for i in range(1, num_pages):
                scrape_hma(str(i), db_client[MONGO_DB])
        else:
            print(error)

    except:
        print(error)

    finally:
        db_client.close()
