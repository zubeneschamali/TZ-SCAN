#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9
'''
Moudle:portscan.py
Last Modified:T20170913

'''

from __future__ import division
from __future__ import unicode_literals 

import sys
import logging
import socket
import nmap
import logging
import threading
import Queue

from IPy import IP
from lib.logging import rewrite_logging

#Config the default encoding
reload(sys)
sys.setdefaultencoding("utf8")

#Filter out the non-HTTP port
nohttp_ports = [21,22,23,25,53,135,137,139,445,873,1433,1521,1723,3306,3389,5800,5900]

class portscan():
    def __init__(self,cidr,domain,threads_num,file_source,ports):
        self.threads_num = threads_num
        self.ports = ports
        self.IPs = Queue.Queue()
        self.file_source = file_source
        self.domain = domain
        self.open_ports = set() #ip-port lists
        self.nohttp_ports = nohttp_ports

        if self.file_source == None:
            if domain == None:
                try:
                    self.cidr = IP(cidr)
                except Exception,e:
                    rewrite_logging('PORTSCAN-ERROR-1',e)
                for ip in self.cidr:
                    ip = str(ip)
                    self.IPs.put(ip)
            else:
                self.IPs.put(domain)
        else:
            with open(self.file_source,'r') as file_ip:
                for line in file_ip:
                    self.IPs.put(line)

    def nmapScan(self):
        with threading.Lock():
            while self.IPs.qsize() > 0:
                item = self.IPs.get()
                try:
                    nmScan = nmap.PortScanner()
                    nmScan.scan(item,arguments = self.ports.read())
                    for tgthost in nmScan.all_hosts():
                        for tgtport in nmScan[tgthost]['tcp']:
                            tgthost = tgthost.strip()
                            tgtport = int(tgtport)
                            if nmScan[tgthost]['tcp'][tgtport]['state'] == 'open':
                                if self.file_source ==None:
                                    if self.domain == None:
                                        open_list = str(tgthost) + ':' + str(tgtport)
                                        message = 'the target %s has opened port %s' % (tgthost,tgtport)
                                        if tgtport not in self.nohttp_ports:
                                            self.open_ports.add(open_list)
                                        rewrite_logging('Result',message)
                                        print message + '\n'
                                    else:
                                        open_list = self.domain + ':' + str(tgtport)
                                        message = 'the target %s has opened port %s' % (self.domain,tgtport)
                                        if tgtport not in self.nohttp_ports:
                                            self.open_ports.add(open_list)
                                        rewrite_logging('Result',message)
                                        print message + '\n'
                                else:
                                    open_list = str(item.strip()) + ':' + str(tgtport)
                                    message = 'the target %s has opened port %s' % (item.strip(),tgtport)
                                    if tgtport not in self.nohttp_ports:
                                        self.open_ports.add(open_list)
                                    rewrite_logging('Result',message)
                                    print message + '\n'
                except Exception, e:
                    if 'PortScanner' in str(e):
                        print 'Error:'
                        print '    You must reinstall module "python-nmap".'
                        print '    Just do \'pip uninstall python-nmap\'.'
                        print '    Then \'pip install python-nmap\'.\n'
                    rewrite_logging('PORTSCAN-ERROR-2',e)
                self.IPs.task_done()            

    def run(self):
        threads = [threading.Thread(target=self.nmapScan) for i in range(self.threads_num)]
        for thread in threads:
            thread.setDaemon(True)
            thread.start()
        for thread in threads:
            thread.join()

        while True:
            if not thread.isAlive():
                break
        return self.open_ports


