#!/usr/bin/python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9
'''
Moudle:cmsscan.py
Last Modified:T20170917

'''

import time
import hashlib
import threading
import requests
import ssl
import Queue
import sys

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
ssl._create_default_https_context = ssl._create_unverified_context
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


#threads_num
threads_num = 10

#Request Timeout
TimeOut = 5

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
          (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36','Connection':'close'}

#Transport adapter" that allows us to use SSLv3
class Ssl3HttpAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv3)

class cmsscan():
    def __init__(self,ip):
        self.IPs = Queue.Queue() #build ip queue
        self.ip = ip
        self.threads_num = threads_num

        #load_cms_file
        cms_list = self.cms_file_load()
        for i in cms_list:
            self.IPs.put(i)

    def scan(self):
        while self.IPs.qsize() > 0:
            cms = self.IPs.get()
            url_cms = self.ip + cms['url']
            try:
                s = requests.Session()
                s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
                r = s.get(str(url_cms).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
                if r.status_code == 200:
                    a = hashlib.md5(r.content).hexdigest()
                    b = cms['md5'].lower()
                    if a == b:
                        #cms_detect(ip,cms['name'])
                        #return cms['name']
                        print '%s detect cms : %s' % (ip,cms['name'])
                        self.IPs.queue.clear()
                    else:
                        pass
            except Exception,e:
                #rewrite_logging('CMSSCAN-ERROR-1','the current ip is %s and the error is %s' % (ip,e))
                print 'current ip is %s,current cms test url is %s' % (ip,cms['url'])
                print e

    def cms_file_load(self):
        try:
            with open('cms.txt','r') as cms_file:
                cms_array = []
                for line in cms_file.readlines():  
                    cms_list = {}
                    cms_str = []
                    cms_str = line.split(',')
                    cms_list['md5'] = cms_str[0]
                    cms_list['url'] = cms_str[1]
                    cms_list['name'] = cms_str[2]
                    cms_array.append(cms_list)
                return cms_array
        except Exception,e:
            #rewrite_logging('CMSSCAN-ERROR-2','the current ip is %s and the error is %s' % (ip,e))
            print e

    def run(self):
        threads = [threading.Thread(target=self.scan) for i in range(self.threads_num)]
        for thread in threads:
            thread.setDaemon(True)
            thread.start()
        for thread in threads:
            thread.join()

        while True:
            if not thread.isAlive():
                break
        #return self.open_ports

def usage():
    print '%s -u ip' % sys.argv[0]

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
        sys.exit(0)
    ip = sys.argv[2]
    cms_scan = cmsscan(ip)
    cms = cms_scan.run()