#coding=utf-8


import re
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

url_cms = 'http://www.baidu.com'
cms_api_url = 'https://00sec.me/api/cms?t=' + url_cms
#url = 'https://124.250.88.16:8080/'
url = 'https://124.250.88.16:8443/'

try:                
    s = requests.Session()
    s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
    r = s.get(str(url).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)

    if r.status_code >= 500:
        print 'False'
    else:
        print 'True'
except Exception,e:
    print e
    print 'False'