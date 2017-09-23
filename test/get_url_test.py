#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import division
from __future__ import unicode_literals 

import re
import sys
import ssl
import time
import logging
import optparse
import requests
import signal
import logging
import threading
import Queue
import urlparse

from lxml import etree
from IPy import IP
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

#from lib.logging import rewrite_logging

#Config the default encoding
reload(sys)
sys.setdefaultencoding("utf8")

#Set the request in ssl with unverified cert and disable_warnings
ssl._create_default_https_context = ssl._create_unverified_context
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#import requests.packages.urllib3.util.ssl_ 
#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

#Request Timeout
TimeOut = 5

#The iterations of the directory
Iterations = 3

#The Deduplicate_lists
Deduplicate_list = set()

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
          (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36','Connection':'close'}

#Transport adapter" that allows us to use SSLv3
class Ssl3HttpAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv3)



def get_url(ip,response):
    try:
        page = etree.HTML((response.text.encode('utf-8')).decode('utf-8'))
    except Exception,e:
        print e
        return
        #rewrite_logging('HTTPSCAN-ERROR-5','the current ip is %s and the error is %s' % (ip,e))
    try:
        reqs = set()
        orig_url = response.url
        print '1111'
        
        #get_href_reqs
        href_url = []        
        link_href_url = page.xpath("//link/@href")
        a_href_url = page.xpath("//a/@href")
        li_href_url = page.xpath("//li/@href")
        href_url = link_href_url + a_href_url + li_href_url
        
        #get_src_reqs
        src_url = []        
        img_src_url = page.xpath("//img/@src")
        script_src_url = page.xpath("//script/@src")
        src_url = img_src_url + script_src_url
        
        all_url = []
        all_url = href_url + src_url
        print '2222'
        #print all_url
        for x in xrange(0,len(all_url)):
            if all_url[x] == None:
                continue
            if '/' not in all_url[x]: #Exclude like 'Javascript:void(0)'
                continue            
            #parse the url not startswith '/' and not startswith 'http',like 'www.test.com/test.html'
            if not all_url[x].startswith('/') and not all_url[x].startswith('http'):
                if url_processor(orig_url)[0].split(':')[0] != all_url[x].split('/')[0]:
                    all_url[x] = '/' + all_url[x]
            #parse the url startswith '//',like '//scripts.test.com/test.html'
            if all_url[x].startswith('//'):
                if url_processor(orig_url)[0].split(':')[0] == all_url[x].split('//')[1].split('/')[0]:
                    all_url[x] = url_processor(orig_url)[1] + all_url[x].split('//')[1]
                else:
                    continue
            reqs.add(url_valid(all_url[x], orig_url))
    except Exception,e:
        print e
    print '3333'

    return list(reqs)

def url_processor(url): # Get the url domain, protocol, and netloc using urlparse
    try:
        parsed_url = urlparse.urlparse(url)
        path = parsed_url.path
        protocol = parsed_url.scheme+'://'
        hostname = parsed_url.hostname
        netloc = parsed_url.netloc
        doc_domain = '.'.join(hostname.split('.')[-2:])
    except Exception,e:
        #rewrite_logging('HTTPSCAN-ERROR-6','Could not parse url: %s' % url)
        print e
        return

    return (netloc, protocol, doc_domain, path)

def url_valid(url,orig_url):
    if url == None:
        return
    if url.startswith('http'): # like https://www.test.com/app/mobile/1.php?id=1
        url_parse = url_processor(url)
        orig_url_parse = url_processor(orig_url)
        if url_parse[0].split(':')[0] != orig_url_parse[0].split(':')[0]:
            return
    elif not url.startswith('/'):# like www.test.com/app/mobile/1.php?id=1
        proc_url = url_processor(orig_url)
        url = proc_url[1] + url
    elif '://' not in url: #like /app/mobile/1.php?id=1
        proc_url = url_processor(orig_url)
        url = proc_url[1] + proc_url[0] + url
    else: 
        proc_url = url_processor(orig_url)
        url = proc_url[1] + url
    return url

if __name__ == '__main__':
    url = 'http://www.pingan.com'
    #url = 'http://www.baidu.com/'
    #url = 'http://202.69.26.1'

    try:
        s = requests.Session()
        s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
        r = s.get(url,headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
        #print r.content
    except Exception,e:
        print e
        print 'tttt'
    
    test_list = get_url(ip=url,response=r)
    for i in test_list:
        print i
    print len(test_list)