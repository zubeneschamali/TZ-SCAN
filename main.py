#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9


from __future__ import division
from __future__ import unicode_literals 

import sys
import optparse

#Config the default encoding
reload(sys)
sys.setdefaultencoding("utf8")

from IPy import IP
from lib.httpscan import httpscan
from lib.portscan import portscan
from lib.cmsscan import cmsscan

def usage():
    print "Example:"
    print "  python "+sys.argv[0]+" -d www.baidu.com"
    print "  python "+sys.argv[0]+" -f domain_list.txt"
    print "  python "+sys.argv[0]+" 1.1.1.0/24"

def quit(signum, frame): #Judge Child Thread's Statue(Exit or Not)!
    print '\nYou choose to stop me!!'
    sys.exit()

def startscan(port,cidr,domain,threads_num,file_source):
    ports = open(port,'r')
    print "------------------------------------------------------------------------------"
    print '# Port Scan Start\n'
    p = portscan(cidr=cidr,domain=domain,threads_num=3,file_source=file_source,ports=ports)
    open_ports = p.run()
    print '# Port Scan Ends'
    print "------------------------------------------------------------------------------"
    print '# Http Scan Start\n'
    h = httpscan(threads_num=threads_num,open_ports=open_ports)
    urls_to_cmsscan = h.run()
    print '# Http Scan Ends'
    print "------------------------------------------------------------------------------"
    print '# Last CMS Scan Start\n'
    for url in urls_to_cmsscan:
        c = cmsscan(url=url,cidr=None,domain=None,file_source=None)
        c.run()
    print '# Last CMS Scan Ends'

if __name__ == "__main__":
    parser = optparse.OptionParser("Usage: %prog [target or file] [options] ")
    parser.add_option("-t", "--thread", dest = "threads_num",
                      default = 100, help = "number of theads,default=100")
    parser.add_option("-d", "--domain", dest = "domain",
                      help = "single domain target")
    parser.add_option("-f", "--file", dest = "file_source",
                      help = "source of file,default=domain_list.txt")
    (options, args) = parser.parse_args()
    
    if len(args) < 1 and options.domain == None and options.file_source == None :
        parser.print_help()
        usage()
        sys.exit(0)
    
    if options.file_source == None:
        if options.domain == None:
            cms_scan_first = cmsscan(url=None,cidr=args[0],domain=None,file_source=None)
            cms_scan_first.run()
            startscan(port='data\port.txt',cidr=args[0],domain=None,
                            threads_num=options.threads_num,file_source=None)
        else:
            cms_scan_first = cmsscan(url=None,cidr=None,domain=options.domain,file_source=None)
            cms_scan_first.run()
            startscan(port='data\port.txt',cidr=None,domain=options.domain,
                            threads_num=options.threads_num,file_source=None)
    else:
        cms_scan_first = cmsscan(url=None,cidr=None,domain=None,file_source=options.file_source)
        cms_scan_first.run()
        startscan(port='data\port.txt',cidr=None,domain=None,threads_num=options.threads_num,
                            file_source=options.file_source)
