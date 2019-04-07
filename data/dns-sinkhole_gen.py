#!/bin/env python3

# Simple DNS sinkhole file generation for DNSCrypt & pdnsd servers
#
# Block DNS query resolutions for specific network domains
#
# Author: Pekka Helenius (~Fincer), 2019
#
########################################

import os
import re
import readline
import signal
import sys
import time

import numpy as np
import urllib.request as URL

from datetime import datetime
from socket import timeout

########################################

url_useragent     = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
url_timeout       = 60
filepath          = '/tmp/'

#timestamp_short   = datetime.now().strftime('%Y-%m-%d')
timestamp_long    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

####################

pdnsd_datafile    = 'pdnsd.sinkhole'
pdnsd_tempfile    = pdnsd_datafile + '.tmp'

pdnsd_fileheader  = "// Auto-generated list, build date " + timestamp_long + "\n// No addresses of these domains must be resolved" + "\n\n"

pdnsd_outmessage  = ("Move it to /etc/ folder and add the following configuration setting in /etc/pdnsd.conf:\n\n" + \
"//Blacklisted domains\ninclude { file = \"/etc/" + pdnsd_datafile + "\"; }\n\n--------------------\nRestart pdnsd by issuing command 'systemctl restart pdnsd'\n")

####################

dnscrypt_datafile   = 'dnscrypt.cloaking.txt'
dnscrypt_tempfile   = dnscrypt_datafile + ".tmp"

dnscrypt_fileheader = "# Auto-generated list, build date " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n# No addresses of these domains must be resolved" + "\n\n"

dnscrypt_outmessage = ("Move it to /etc/dnscrypt-proxy/ and add the following configuration setting in\n/etc/dnscrypt-proxy/dnscrypt-proxy.toml:\n\n" + \
"cloaking_rules = '/etc/dnscrypt-proxy/" + dnscrypt_datafile + "'\n\n--------------------\nRestart dnscrypt-proxy by issuing command 'systemctl restart dnscrypt-proxy'\n")

########################################

domains_blacklists = [
#    {
#      'name': 'Cameleon blocklist',
#      'url':  'https://sysctl.org/cameleon/hosts'
#    },
#    {
#      'name': 'Xiaomi spyware blocklist (kevle2)',
#      'url':  'https://raw.githubusercontent.com/kevle2/XiaomiSpywareBlockList/master/xiaomiblock.txt'
#    },
    {
      'name': 'My custom blocklist',
      'url':  'file:///home/' + os.environ['USER']  + '/dns-sinkhole.txt'
    },
    {
      'name': 'Simple tracking',
      'url':  'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt'
    },
    {
      'name': 'Simple ads',
      'url':  'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt'
    },
    {
      'name': 'Zeustracker blocklist',
      'url':  'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
    },
    {
      'name': 'Zeustracker baddomains',
      'url':  'https://zeustracker.abuse.ch/blocklist.php?download=baddomains'
    },
    { 
      'name': 'StevenBlack blocklist',
      'url':  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    },
    { 
      'name': 'Malwaredomains blocklist',
      'url':  'https://mirror1.malwaredomains.com/files/justdomains'
    },
    {
      'name': 'Ad servers',
      'url':  'https://hosts-file.net/ad_servers.txt'
    },
    {
      'name': 'YouTube ads (kboghdady)',
      'url':  'https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/black.list'
    },
    {
      'name': 'YouTube ads (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/youtube.txt'
    },
    {
      'name': 'HbbTV ads (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/hbbtv.txt'
    },
    {
      'name': 'Windows ads (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/nomsdata.txt'
    },
    {
      'name': 'Android & iOS ads (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/appads.txt'
    },
    {
      'name': 'Fake jailbreak websites (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/jbfake.txt'
    },
    {
      'name': 'Adobe updates (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/adobeblock.txt'
    },
    {
      'name': 'Fake emulators (Akamaru)',
      'url':  'https://raw.githubusercontent.com/Akamaru/Pi-Hole-Lists/master/gamefake.txt'
    },
    {
      'name': 'ADsecu blocklist',
      'url':  'https://raw.githubusercontent.com/ADsecu/black-domains/master/domain_hosts.txt'
    },
    {
      'name': 'SweetSophia blocklist',
      'url':  'https://raw.githubusercontent.com/SweetSophia/mifitxiaomipiholelist/master/mifitblocklist.txt'
    },
    {
      'name': 'Android ads (SweetSophia)',
      'url':  'https://raw.githubusercontent.com/SweetSophia/androidappspihole/master/testrareandroappblock.txt'
    },
    {
      'name': 'Blocklist (zebpalmer)',
      'url':  'https://raw.githubusercontent.com/zebpalmer/dns_blocklists/master/blocklist.txt'
    },
    {
      'name': 'Ads and tracking extended (lightswitch05)',
      'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt'
    },
    {
      'name': 'Amp hosts extended (lightswitch05)',
      'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/amp-hosts-extended.txt'
    },
    {
      'name': 'Tracking aggressive (lightswitch05)',
      'url':  'https://raw.githubusercontent.com/lightswitch05/hosts/master/tracking-aggressive-extended.txt'
    },
    {
      'name': 'dnscrypt.info blacklist',
      'url':  'https://download.dnscrypt.info/blacklists/domains/mybase.txt'
    },
    {
      'name': 'dnscrypt-proxy blacklist',
      'url':  'https://raw.githubusercontent.com/CNMan/dnscrypt-proxy-config/master/dnscrypt-blacklist-domains.txt'
    },
    {
      'name': 'dnscrypt - activation blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/activation.txt'
    },
    {
      'name': 'dnscrypt - ads blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/ads.txt'
    },
    {
      'name': 'dnscrypt - anticheat blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/anticheat.txt'
    },
    {
      'name': 'dnscrypt - fakenews blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/fakenews.txt'
    },
    {
      'name': 'dnscrypt - tracking blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/tracking.txt'
    },
    {
      'name': 'dnscrypt - misc blocklist',
      'url':  'https://raw.githubusercontent.com/zeffy/dnscrypt-blocking-additions/master/hosts/blacklist/misc.txt'
    },
    {
      'name': 'WindowsSpyBlocker - spy (crazy-max)',
      'url':  'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/dnscrypt/spy.txt'
    },
    {
      'name': 'WindowsSpyBlocker - update (crazy-max)',
      'url':  'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/dnscrypt/update.txt'
    },
    {
      'name': 'WindowsSpyBlocker - extra (crazy-max)',
      'url':  'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/dnscrypt/extra.txt'
    }
]

########################################
# Exclude these pre-blacklisted domains from the final DNS sinkhole blacklist

domains_whitelists = [
    {
      'name': 'My custom whitelist',
      'url':  'file:///home/' + os.environ['USER']  + '/dns-whitelist.txt'
    }
]

########################################

failedlists = []

##########
def filewrite(filepath, datafile, string, operationmode, closefile):
    with open(os.path.join(filepath, datafile),operationmode) as f:
        f.write(string)
    if closefile is True:
      f.close()

##########
def getlist(domainlist,timeout):
    if not domainlist is None:
        try:
            print("Processing list:\t\t" + domainlist['name'])
            request = URL.Request(domainlist['url'],headers={'User-Agent': url_useragent})
            return np.array(URL.urlopen(request, timeout=timeout).read().decode('utf-8').split('\n'))

        except KeyboardInterrupt:
            exit(0)

        except:
            print("Data retrieval failed:\t\t" + domainlist['url'] + "\n")
            failedlists.append(domainlist['name'])
            pass

##########
def fetchdomaindata(dataset):
    fetched_data = set()
    if not dataset is None:
        for line in dataset:
            if not re.search('.*:.*', line) \
            and not re.search('[\[|\]]', line) \
            and not re.search('^.*#', line) \
            and not re.search('.*localhost.*', line) \
            and not re.search('\slocal$', line) \
            and not re.search('^$', line) \
            and re.search('[a-z]+', line):
                line = re.sub(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ \t]+','',line)

                # Windows EOL last character substitution, corrects misformatted line variable
                line = re.sub('[\n]?\r$','',line)

                if not re.match('^$',line):
                    fetched_data.add(line)

        if len(set(fetched_data)) == 0:
            print("\t\t\t\tNo domain entries found\n")

        return fetched_data

########################################
# DNS sinkhole file headers

filewrite(filepath, pdnsd_datafile, pdnsd_fileheader, 'w', True)
filewrite(filepath, dnscrypt_datafile, dnscrypt_fileheader, 'w', True)

####################
# Download and parse white/blocklists

##########
for whitelist in domains_whitelists:
    whitelist_dataset = getlist(whitelist, url_timeout)

whitelist_fetched_data = fetchdomaindata(whitelist_dataset)

##########
for blacklist in domains_blacklists:
    blacklist_dataset = getlist(blacklist, url_timeout)

    if not blacklist_dataset is None:
        for line in (fetchdomaindata(blacklist_dataset)):

                if not line in whitelist_fetched_data:

                    if re.search('^\.', line):
                        pdnsd_line    = "neg { name=*" + line + "; types = domain; }"
                    elif re.search('\*', line):
                        pdnsd_line    = "neg { name=" + line + "; types = domain; }"
                    else:
                        pdnsd_line    = "rr { name=" + line + "; a=0.0.0.0; }"
                        dnscrypt_line = line + " " + "0.0.0.0"

                    filewrite(filepath, pdnsd_tempfile, pdnsd_line + '\n', 'a', False)

                    if not dnscrypt_line is None:
                        filewrite(filepath, dnscrypt_tempfile, dnscrypt_line + '\n', 'a', False)

####################
# Parse generated list, get only unique lines and write to final file
def parseuniqlines(filepath, tempfile, outfile, outmessage):
  uniqdata = set()
  with open(os.path.join(filepath, outfile),'a') as f:
      for line in open(os.path.join(filepath, tempfile),'r'):
          if not line in uniqdata:
              f.write(line)
              uniqdata.add(line)
      f.close()
  os.remove(os.path.join(filepath, tempfile))
  print("----------------------------------------")
  print("Added " + str(len(set(uniqdata))) + " unique domains to the sinkhole file " + filepath + outfile)
  print("DNS sinkhole file " + filepath + outfile + " generated successfully.")
  print(outmessage)

parseuniqlines(filepath, pdnsd_tempfile, pdnsd_datafile, pdnsd_outmessage)
parseuniqlines(filepath, dnscrypt_tempfile, dnscrypt_datafile, dnscrypt_outmessage)

####################
# Inform user about failed DNS blocklist downloads
if len(failedlists) > 0:
    print("Warning: could not get data for the following blocklists:\n")
    for i in range(len(failedlists)):
        print("\t" + failedlists[i])
    print("")
