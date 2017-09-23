# TZ-SCAN
HTTPSCAN-V2

httpscan --
|
|-------data ----
|                port.txt       (常见端口)
|                dict.txt       (常见目录及页面)
|                dict_all.txt   (所有目录及页面)
|-------result ----
|                httpscan_result.txt     (工具扫描结果文件)
|                httpscan_info.txt       (工具扫描信息文件)
|                httpscan_error.txt      (工具扫描错误文件)
|                cms_detect.txt          (cms扫描结果文件)
|                reqs_record_all.txt     (工具扫描所有的请求链接文件)
|-------lib ----
|                portscan.py    (端口扫描程序)
|                httpscan.py    (http扫描程序)
|                cmsscan.py     (cms 扫描程序)
|                logging.py     (日志记录程序)
|-------plugin ----
|                各类漏洞插件         (漏洞扫描插件)
|                弱口令扫描（ftp、ssh、telnet、mysql、msssql、phpmyadmin等等）