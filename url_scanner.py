'''
Required libraries/modules ---

requests,
BeautifulSoup4
tldextract
'''


'''
Normal Crawl -- python3 url_scanner.py -u http://testsite.com

Show Fuzzable -- Links python3 url_scanner.py -u http://testsite.com -f

Show External Links -- python3 url_scanner.py -u http://testsite.com -e

DeepCrawl and Show Fuzzable Links -- python3 url_scanner.py -u -d http://testsite.com -f
'''

import requests 
import bs4 
import argparse
import json
import re
from urllib.parse import urlparse
import tldextract

external = []
unknown =  []
fuzzables = []

def write2configJson(data, filename = "config.json"):

    fileObj = None

    try:
        fileObj = open(filename, "w")
        json.dump(data, fileObj, ensure_ascii=True, indent=4)
    except Exception as e:
        print("\n\n\write file error: \n\n" + str(e))



def readConfigJson(filename = "config.json"):

    fin = None
    data = None

    try:
        fin = open(filename, "r", encoding="utf-8-sig")
        data = fin.read()
        data = json.loads(data)
    except Exception as e:
        print("\n\n\read from file error: \n\n" + str(e))

    return data


def isValidUrl(url):

    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None


def getDomain(url):
    parsed_uri = urlparse(url)
    tld = tldextract.extract(url)
    domain = '{uri.scheme}://{tld.domain}.{tld.suffix}/'.format(uri=parsed_uri,tld=tld)
    return domain

    
def addUrl2ConfigJson(jsonObj, url):

    domain = getDomain(url)
    
    if isValidUrl(url) == True and domain not in jsonObj["root_urls"]:
        jsonObj["root_urls"].append(domain)


def extractor(soup , host) : 
	all_links = list()
	for link in soup.find_all('a' , href = True) :
		if link['href'].startswith('/') : 
			if link['href'] not in all_links : 
				all_links.append(host+link['href'])
		elif host in link['href'] : 
			if link['href'] not in all_links : 
				all_links.append( link['href'] )
		elif 'http://' in host : 
			if 'https://'+host.split('http://')[1] in link['href'] and link['href'] not in all_links: 
					all_links.append( link['href'] )
		elif 'http' not in link['href'] and 'www' not in link['href'] and len(link['href']) > 2 and '#' not in  link['href'] : 
			if link['href'] not in all_links : 
				all_links.append(host+'/'+link['href'])
		elif len (link['href']) > 6 : 
			external.append( link['href'] )
		else : 
			unknown.append( link['href'] )
	return all_links
	
	
def fuzzable_extract(linklist):
	fuzzables = []
	for link in linklist : 
		if "=" in link : 
			fuzzables.append(link)
	return fuzzables 	
def xploit(link , host = None) : 
	if host is None : 
		host = link
	res = requests.get(link , allow_redirects=True)
	soup = bs4.BeautifulSoup(res.text , 'lxml')
	return extractor(soup , host)
	
def level2(linklist , host) : 
	final_list = list()
	for link in linklist : 
		for x in xploit(link , host) :
			if x not in final_list : 
					final_list.append(x)
					print("Appended" , x)
		if link not in final_list : 
			final_list.append(link)
	return final_list
def main() : 

	configJson = readConfigJson()

	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', help='root url', dest='url')
	parser.add_argument('-d', '--deepcrawl', help='crawl deaply', dest='deepcrawl', action='store_true')
	parser.add_argument('-f', '--fuzzable', help='extract fuzzable', dest='fuzzable', action='store_true')
	parser.add_argument('-e', '--external', help='extract external', dest='external', action='store_true')
	args = parser.parse_args()
	if args.url is None : 
		quit()
	if 'http' not in args.url : 
		args.url = 'http://' + args.url 
	if args.deepcrawl : 
		links = level2(xploit(args.url) , args.url)
		if len(links) > 1 : 
			print('\n\nLINKS WITH DEEPCRAWL : \n\n')
			for link in links : 
				print('>\t' , link)
				addUrl2ConfigJson(configJson, link)
		else : 
			print ('\n\nNo Link Found\n\n')
	else : 
		links =xploit(args.url)
		if len(links) > 1 : 
			print('\n\nLINKS : \n\n')
			for link in links : 
				print('>\t' , link)
				addUrl2ConfigJson(configJson, link)
		else : 
			print ('\n\nNo Link Found\n\n')

	if args.fuzzable : 
		if  len(links) > 1 : 
			if len(fuzzable_extract(links)) > 1 : 
				print('\n\nFUZZABLE LINKS : \n\n')
				for link in fuzzable_extract(links) : 
					print('>\t' , link)
					addUrl2ConfigJson(configJson, link)
			else : 
				print ('\n\nNo Fuzzable Link Found\n\n')


	if args.external : 
		if  len(external) > 1 : 
				print('\n\nEXTERNAL LINKS : \n\n')
				for link in external : 
					print('>\t' , link)
					addUrl2ConfigJson(configJson, link)
		else : 
				print ('\n\nNo EXTERNAL Link Found\n\n')

	write2configJson(configJson)				

main()
		
		
	
	