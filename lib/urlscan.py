#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9
'''
Moudle:urlscan.py
Last Modified:T20170916

'''

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

from lib.logging import rewrite_logging

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
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv3)

class urlscan():
    def __init__(self,threads_num,open_ports):
        self.threads_num = threads_num
        self.IPs = Queue.Queue() #build ip queue
        self.open_ports = open_ports
        self.dict_list_file = 'data\dict.txt' #open the path dictionary

        #Process Bar Config
        with open(self.dict_list_file,'r') as dict_lists:
            self.dict_num = len(dict_lists.readlines())
        self.port_num = len(open_ports)
        self.all_num = (self.port_num * self.dict_num)* 2
        self.bar = '#'
        
        #parse the robot.txt
        robot_directory_list = self.robot_txt_parse()
        for url in robot_directory_list:
            self.IPs.put(url)
            rewrite_logging('INFO','rejoin the url directory from Robot.txt :  %s' % url)

        #self.test = test_list
        with open(self.dict_list_file,'r') as dict_lists:
            for dict_line in dict_lists.readlines():
                dict_line = dict_line.strip()
                for open_port in list(self.open_ports):
                    if open_port.strip().endswith('80'):
                        self.IPs.put("http://"+str(open_port)+str(dict_line))
                    elif open_port.strip().endswith('443'):
                        self.IPs.put("https://"+str(open_port)+str(dict_line))
                    else:
                        self.IPs.put("http://"+str(open_port)+str(dict_line))
                        self.IPs.put("https://"+str(open_port)+str(dict_line))
        self.qsize = self.IPs.qsize()

    def redirect_handler_func(self,ip,location):
        loc_urlparse = urlparse.urlparse(location)
        ip_urlparse = urlparse.urlparse(ip)
        if loc_urlparse.netloc.split(':')[0] == ip_urlparse.netloc.split(':')[0]:
            if location.strip() not in Deduplicate_list:
                self.IPs.put(location.strip())
                Deduplicate_list.add(location.strip())
                rewrite_logging('INFO','rejoin the 302 url:  %s' % location)

            #rejoin the url_directory of locations
            if location != None:
                location_url_directory_lists = self.url_parse_func(location)
                if location_url_directory_lists != None:
                    for x in xrange (0,len(location_url_directory_lists)):
                        url_directory_list = location_url_directory_lists[x]
                        if url_directory_list not in Deduplicate_list:
                            self.IPs.put(url_directory_list)
                            Deduplicate_list.add(url_directory_list)
                            rewrite_logging('INFO','rejoin the url directory from url of 301/302 :  %s' % url_directory_list)

    def str_replace(self,ip): #Replace 'https://test.com//1//2//3//4/(//)' to 'https://test.com/1/2/3/4/'
        new_ip = ip.split('://')[0] + '://'
        new_ip = new_ip + ip.split('://')[1].replace('//','/')
        return new_ip

    def log_func(self,ip,ip_original,status,banner,title):
        if (status != 400) and (status != 403) and (status != 404) and ('404' not in str(title)):
            self.print_log(ip,status,banner,title)
        if (status != 400) and (status != 404) and ('404' not in str(title)):
            self.rejoin_queue(ip,ip_original,status)

    def rejoin_queue(self,ip,ip_original,status):
        if (ip.strip().endswith('/')):
            if (status == 200) or (status == 403) or (status == 501):
                with open(self.dict_list_file,'r') as dict_lists:
                    for dict_line in dict_lists.readlines():
                        dict_line = dict_line.strip()
                        if dict_line != '/':
                            rejoin_queue_ip = str(ip).strip() + str(dict_line)
                            rejoin_queue_ip_original = str(ip_original).strip() + str(dict_line)
                            if rejoin_queue_ip_original.count('//') <= (Iterations+1): #Judge the count of Iterations
                                if (rejoin_queue_ip_original not in Deduplicate_list) and \
                                    (rejoin_queue_ip not in Deduplicate_list):
                                    self.IPs.put(rejoin_queue_ip_original)
                                    self.qsize += self.dict_num
                            Deduplicate_list.add(rejoin_queue_ip)
                            Deduplicate_list.add(rejoin_queue_ip_original)
    
    def print_log(self,ip,status,banner,title):
        message = "|%-66s|%-6s|%-14s|%-30s|" % (ip.strip(),status,banner,title)
        rewrite_logging('Result',message)

    def get_url(self,ip,response):
        try:
            page = etree.HTML((response.text.encode('utf-8')).decode('utf-8'))
        except Exception,e:
            return
            rewrite_logging('HTTPSCAN-ERROR-5','the current ip is %s and the error is %s' % (ip,e))
        reqs = set()
        orig_url = response.url
    
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

        for x in xrange(0,len(all_url)):
            if all_url[x] == None:
                continue
            if '/' not in all_url[x]: #Exclude like 'Javascript:void(0)'
                continue
            
            #parse the url not startswith '/' and not startswith 'http',like 'www.test.com/test.html'
            if not all_url[x].startswith('/') and not all_url[x].startswith('http'):
                if self.url_processor(orig_url)[0].split(':')[0] != all_url[x].split('/')[0]:
                    all_url[x] = '/' + all_url[x]

            #parse the url startswith '//',like '//scripts.test.com/test.html'
            if all_url[x].startswith('//'):
                if self.url_processor(orig_url)[0].split(':')[0] == all_url[x].split('//')[1].split('/')[0]:
                    all_url[x] = self.url_processor(orig_url)[1] + all_url[x].split('//')[1]
                else:
                    continue

            reqs.add(self.url_valid(all_url[x], orig_url))

        return list(reqs)

    def url_valid(self,url,orig_url):
        if url == None:
            return
        if url.startswith('http'): # like https://www.test.com/app/mobile/1.php?id=1
            url_parse = self.url_processor(url)
            orig_url_parse = self.url_processor(orig_url)
            if url_parse[0].split(':')[0] != orig_url_parse[0].split(':')[0]:
                return
        elif not url.startswith('/'):# like www.test.com/app/mobile/1.php?id=1
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + url
        elif '://' not in url: #like /app/mobile/1.php?id=1
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + proc_url[0] + url
        else: 
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + url
        return url
    
    def url_processor(self,url): # Get the url domain, protocol, and netloc using urlparse
        try:
            parsed_url = urlparse.urlparse(url)
            path = parsed_url.path
            protocol = parsed_url.scheme+'://'
            hostname = parsed_url.hostname
            netloc = parsed_url.netloc
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            rewrite_logging('HTTPSCAN-ERROR-6','Could not parse url: %s' % url)
            return
    
        return (netloc, protocol, doc_domain, path)
    
    def progress_bar(self,unfinished_num):
        #sys.stdout.write(str(int((qsize/self.all_num)*100))+'% '+bar+'->'+ "\r")
        finished_num = self.qsize - unfinished_num
        sys.stdout.write(str(int((finished_num/self.qsize)*100))+'% ')
        sys.stdout.flush()
        #time.sleep(0.5)
        #print
        #return

    def url_parse_func(self,url):
        #when the url is like 'https://www.test.com/1/2/3/4.php?id=4' 
        #put 'https://www.test.com/1/' and 'https://www.test.com/1/2/' and 'https://www.test.com/1/2/3/' to the queue
        url_par = urlparse.urlparse(url)
        url_split = url_par.path.split('/')
        url_new = '/'
        url_list = set()
        if len(url_split) >= 3:
            for x in xrange(1,(len(url_split)-1)):
                url_new = url_new+url_split[x]+'/'
                url_list.add(url_par.scheme+'://'+url_par.netloc+url_new)
        
        return list(url_list)
    
    def url_unparse_func(self,url):
        #when the url is like 'https://www.baidu.com:443/1/2/3/4.php?id=1'
        #return 'https://www.baidu.com:443/1/2/3/4.php?id=1' and 'https://www.baidu.com/1/2/3/4.php?id=1' to put to the Deduplicate_list
        url_parse = urlparse.urlparse(url)
        if len(url_parse.netloc.split(':')) > 1:
            if (url_parse.netloc.split(':')[1] == '80') or (url_parse.netloc.split(':')[1] == '443'):
                netloc = url_parse.netloc.split(':')[0]
                return urlparse.urlunparse((url_parse.scheme,netloc,url_parse.path,url_parse.params,url_parse.query,url_parse.fragment))

    def robot_txt_parse(self):
        url = ''
        robot_directory = set()

        try:
            for open_port in list(self.open_ports):
                if open_port.strip('').endswith('80'):
                    url = "http://"+str(open_port)+'/robot.txt'
                    dictory = self.robot_parse_process(url)
                    if dictory == None:
                        continue
                    for i in dictory:
                        robot_directory.add("http://"+str(open_port)+i)
                elif open_port.strip().endswith('443'):
                    url = "https://"+str(open_port)+'/robot.txt'
                    dictory = self.robot_parse_process(url)
                    if dictory == None:
                        continue
                    for i in dictory:
                        robot_directory.add("http://"+str(open_port)+i)
                else:
                    url_http = "http://"+str(open_port)+'/robot.txt'
                    url_https = "https://"+str(open_port)+'/robot.txt'
                    dictory_http = self.robot_parse_process(url_http)
                    if dictory_http == None:
                        continue
                    for i in dictory_http:      
                        robot_directory.add("http://"+str(open_port)+i)                          
                    dictory_https = self.robot_parse_process(url_https)
                    if dictory_https == None:
                        continue
                    for i in dictory_https:
                        robot_directory.add("https://"+str(open_port)+i)
        except Exception,e:
            rewrite_logging('HTTPSCAN-ERROR-7','the error is %s' % e)

        return list(robot_directory)

    def robot_parse_process(self,url):
        directory_list = set()
        try:
            s = requests.Session()
            s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
            r = s.get(str(url).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
            
            res_para = self.get_response_para(ip=url,response=r)
            status = res_para[0]

            if status == 200:
                disallow_str = re.findall(r'Disallow: \S+',r.content)
                for i in disallow_str:
                    i = i.replace("*","/")
                    i = i.replace('&','/')
                    i = i.replace('///','/')
                    i = i.replace('//','/')
                    i = i.split(': ')[1]
                    if i == '/':
                        continue
                    if i.endswith('/'):
                        directory_list.add(i)
            else:
                return
        except Exception,e:
            rewrite_logging('HTTPSCAN-ERROR-8','the current url is %s and the error is %s' % (url,e))
        
        return list(directory_list)