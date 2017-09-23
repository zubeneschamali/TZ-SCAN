#!/usr/bin/python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9
'''
Moudle:cmsscan.py
Last Modified:T20170922

'''

import time
import hashlib
import threading
import requests
import ssl
import Queue
import sys

from IPy import IP
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
ssl._create_default_https_context = ssl._create_unverified_context
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.logging import cms_detect_log
from lib.logging import rewrite_logging

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
    def __init__(self,url,cidr,domain,file_source):
        self.IPs_api = Queue.Queue()
        self.IPs_md5 = Queue.Queue()
        self.threads_num = threads_num
        self.ip = url
        self.cidr = cidr
        self.domain = domain
        self.file_source = file_source
        
    def scan_api(self):
        while self.IPs_api.qsize() > 0:
            url_detect = self.IPs_api.get()
            cms_api_url = 'https://00sec.me/api/cms?t=' + url_detect
            try:
                api_s = requests.Session()
                api_s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
                api_r = api_s.get(str(cms_api_url).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
                res_list = api_r.content.split('\n')

                cms_detect = res_list[2].split(':')[1].split('"')[1]
                if (cms_detect == 'unknown') or (cms_detect == 'None'):
                    #if scan_api cannot detect the cms,goto scan_md5
                    self.ip = url_detect
                    self.run()
                else:
                    cms_detect_log(url_detect,cms_detect)
                    print '%s discovery cms : %s' % (url_detect,cms_detect)
                    print ''
                    self.IPs_api.queue.clear()
            except Exception,e:
                rewrite_logging('CMSSCAN-ERROR-1','ip is %s , error is %s' % (url_detect,e))

    def scan_md5(self):
        while self.IPs_md5.qsize() > 0:
            cms = self.IPs_md5.get()
            url_cms = self.ip + cms['url']
            
            #cms md5 detect
            try:
                s = requests.Session()
                s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
                r = s.get(str(url_cms).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
                if r.status_code == 200:
                    a = hashlib.md5(r.content).hexdigest()
                    b = cms['md5'].lower()
                    if a == b:
                        cms_detect(self.ip,cms['name'])
                        print '%s discovery cms : %s' % (self.ip,cms['name'])
                        self.IPs_md5.queue.clear()
            except Exception,e:
                if 'Connection aborted' in str(e):
                    pass
                elif 'HTTPConnectionPool' in str(e):
                    pass
                elif 'HTTPSConnectionPool' in str(e):
                    pass
                else:
                    rewrite_logging('CMSSCAN-ERROR-2','ip is %s ,cms url is %s, error is %s' % (self.ip,cms['url'],e))

    def cms_file_load(self):
        try:
            with open('data\cms.txt','r') as cms_file:
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
            rewrite_logging('CMSSCAN-ERROR-3','the error is %s' % e)

    def run(self):
        if self.ip == None:
            self.cms_first_detect()
        else:
            #load_cms_file and join urls to queue
            cms_list = self.cms_file_load()
            for i in cms_list:
                #url_cms = url + i['url']
                self.IPs_md5.put(i)
            threads = [threading.Thread(target=self.scan_md5) for i in range(self.threads_num)]
            for thread in threads:
                thread.setDaemon(True)
                thread.start()
            for thread in threads:
                thread.join()

            while True:
                if not thread.isAlive():
                    break

    def cms_first_detect(self):
        print "------------------------------------------------------------------------------"
        print '# First CMS Scan Start\n'
        if (self.cidr == None) and (self.domain == None):
            with open(self.file_source,'r') as f:
                for line in f.readlines():
                    self.cms_scan_process(ip=line)
        elif (self.cidr == None) and (self.file_source == None):
            self.cms_scan_process(ip=self.domain)
        else:
            ips = IP(self.cidr)
            for ip in ips:
                ip = str(ip)
                self.cms_scan_process(ip)
        print '# First CMS Scan Ends'

    def cms_scan_process(self,ip):
        url_http = 'http://' + ip
        url_https = 'https://' + ip
        s = requests.Session()
        s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3

        #http test
        try:
            r_http = s.get(str(url_http).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
            if r_http.status_code >= 500:
                pass
            else:
                self.IPs_api.put(url_http)
        except Exception,e:
            rewrite_logging('CMSSCAN-ERROR-4','the current url is %s and the error is %s' % (ip,e))
            self.ip = url_http
            self.run()
        
        #https test
        try:
            r_https = s.get(str(url_https).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
            if r_https.status_code >= 500:
                pass
            else:
                self.IPs_api.put(url_https)
            self.scan_api()
        except Exception,e:
            rewrite_logging('CMSSCAN-ERROR-5','the current url is %s and the error is %s' % (ip,e))
            self.ip = url_https
            self.run()