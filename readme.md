
# Apache log parser v1.0
Scaner for Apache log files on POST-requests for search malware in site files which can be hidden from usual analyzers.

# Description

PHP parser for scanning typical Apache log files on suspected POST requests, which can be performed for activate spam-generating viruses on spam sending. With this parser, I can discover virus code which did not detect traditional virus analyzers of site files.

The Script analyzes the Apache logs of the following format:

54.205.12.6 - - [02/Jan/2018:00:01:54 +0300] "GET http://www.site1.ru/" 404 1022 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36" 127.0.0.12

83.102.198.205 - - [02/Jan/2018:00:01:58 +0300] "GET http://site2.spb.su/" 200 104980 "-" "PycURL/7.43.0 libcurl/7.38.0 OpenSSL/1.0.1 zlib/1.2.3.4 c-ares/1.7.5 libidn/1.23 libssh2/1.2.8 librtmp/2.3" 127.0.0.10

178.154.171.16 - - [02/Jan/2018:00:02:08 +0300] "GET http://www.edemavto.ru/sites/default/files/remon-vnedorozhniki.png" 304 0 "-" "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)" -

31.130.7.249 - - [02/Jan/2018:00:26:35 +0300] "POST http://site3.sitehosting.msk.su/" 200 25332 "http://infiniti.service.msk.su/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36" 127.0.0.11

Of course, not all POST-requests are malicious -  for example, a normal user login to a personal cabinet or sending various contact forms. However, the high frequency of the same POST-request or an unusual request address (e.g. http://site.com/wp-admin/plugins/sendmessage.php) which is not typical for normal POST-requests - may indicate an attempt to crack the administrative password or the repeated activation of the previously introduced malicious code with an external signal.

## Getting Started

How use Script for your server.

0) Download script to your working computer;

1) Please, check up that log file (which you are going to analyze) have appropriate format (see above);

2) By default, the script analyzes the demo log file from its root directory (file name hardcoded in line 9 of script: define('LOCAL_LOGPATH', "demo_log.0"); ).

3) For correct use the Script:
a) you must edit logparser.php file and specify the correct path to the server's log folder and the file name of Apache access log - in line 10, see define('TEST_LOGPATH', "<your-path>");1

b) you must change (see line 12) $logpath = DEMO_LOGPATH; to $logpath = TEST_LOGPATH;

c) if your site has many knowning repetitive POST-requests (e.g. for the regular launch of a certain service by this way), you should specify theirs URLs in the white list - in line 15, edit list in array:
$whitelist = array(' ...

d) move script to the www/public_html directory of the investigated server and enter the full path to the script from the root of the available site in whose folder the script was placed - in the your browser's address bar.

e) Enjoy it! Example of parsing log in the browser:
![alt text](https://raw.githubusercontent.com/NDanilov2015/apache-logparser/master/apache-lp-demo.png)

You can see POST-requests data + number of their repetition since the log file creation time, usually since the last rotation of the logs.

Script use sorting by the number of requests - the highest-frequency requests (which can be regarded as the most suspicious) are shown at the top of the list.

### Prerequisites

a) This app compatible with any client browsers.

b) This app require PHP interpreter version > 5.2.0 on the server side.

## Built With
* [PHP language](http://www.php.net/) - The Hypertext PreProcessor language :)

## Change log
From 02.01.2018 - v1.0