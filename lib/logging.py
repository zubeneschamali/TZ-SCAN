#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author: 挑战自我
#Version: 1.9
'''
Moudle:logging.py
Last Modified:T20170921
'''

import time
import codecs

#Log-Config
logging_file_result = codecs.open('result\httpscan_result.txt','wb',encoding = 'utf-8')
logging_file_info = codecs.open('result\httpscan_info.txt','wb',encoding = 'utf-8')
logging_file_error = codecs.open('result\httpscan_error.txt','wb',encoding = 'utf-8')

#reqs_record
reqs_record_file = codecs.open(r'result\reqs_record_all.txt','wb',encoding = 'utf-8')

#cms_detect
logging_file_cms_detect = codecs.open('result\cms_detect.txt','wb',encoding = 'utf-8')

def rewrite_logging(level,message):
    log = "[%s] %s: %s" % (time.asctime(),level,message)
    if 'Result' in level:
        logging_file_result.write(log)
        logging_file_result.write('\n')
    elif 'ERROR' in level:
        logging_file_error.write(log)
        logging_file_error.write('\n')
    else:
        logging_file_info.write(log)
        logging_file_info.write('\n')

def reqs_record_all(ip):
    req = "[%s] : %s" % (time.asctime(),ip)
    reqs_record_file.write(req)
    reqs_record_file.write('\n')

def cms_detect_log(ip,cms):
    cms_detect = "[%s] : %s : %s" % (time.asctime(),ip,cms)
    logging_file_cms_detect.write(cms_detect)
    logging_file_cms_detect.write('\n')
