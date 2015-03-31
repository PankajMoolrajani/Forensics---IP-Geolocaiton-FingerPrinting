import urllib
import json
import re
import subprocess
import pythonwhois

from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Base, DomainInfo

def main(url):
	loc_api = 'http://ip-api.com/json/'
	list_domains, list_urls = getListUrls(url)
	file_kml = open("geoip.kml", "w")
	file_report = open("report.txt", "w")
	makeKml("", "", "", "start", file_kml)
	session = createDbSession()
	while len(list_domains) > 0:
		for domain in list_domains:
			try:
				list_domains, whois = getWhoIs(list_domains, domain)
				if whois == "":
					break
				whois['domain'] = domain
				whois['ip'] = getIP(domain)
				loc = json.loads(urllib.urlopen(loc_api+whois['ip']).read())
				whois['lat'] = str(loc['lat'])
				whois['lon'] = str(loc['lon'])

				for url in list_urls:
					if domain in url:
						whois['url'] = url
						whois['fp'] = getServerFingerprint(url, whois)
			
				printShell(whois)
				makeKml(domain, whois['lat'], whois['lon'], "placemarker", file_kml)
				insertIntoDB(session, whois)
				writeReport(file_report, whois)
			except:
				pass	
	session.commit()
	makeKml("", "", "", "end", file_kml)
	file_report.close()

def printShell(whois):
	try:
		print "Domain: "+str(whois['domain'])
		print "IP: "+str(whois['ip'])
		print "Location: "+"Latitude-"+str(whois['lat'])+" Longitude-"+str(whois['lon'])
		print "Whois: "+str(whois)
		print "Fingerprint: "+str(whois['fp'])
		print "-"*150
		print "\n\n"
	except:
		pass

def writeReport(file_report, whois):
	file_report.write("Domain: "+str(whois['domain'])+"\n\n")
	file_report.write("IP: "+str(whois['ip'])+"\n\n")
	file_report.write("Location: "+"Latitude-"+str(whois['lat'])+" Longitude-"+str(whois['lon'])+"\n\n")
	file_report.write("Whois: "+str(whois)+"\n\n")
	file_report.write("Fingerprint: "+str(whois['fp'])+"\n\n")
	file_report.write("\n\n")
	file_report.write("-"*150)
	file_report.write("\n\n")
	
def getServerFingerprint(url, whois):
	dict_fp = {}
	try:
		dict_headers = urllib.urlopen(whois['url']).headers.dict
		if 'server' in dict_headers.keys():
			dict_fp['server'] = dict_headers['server']
		if 'date' in dict_headers.keys():
			dict_fp['timestamp'] = dict_headers['date']
		if 'x-frame-options' in dict_headers.keys():
			dict_fp['x-frame-options'] = dict_headers['x-frame-options']
		if 'x-xss-protection' in dict_headers.keys():
			dict_fp['x-xss-protection'] = dict_headers['x-xss-protection']
		if 'cache-control' in dict_headers.keys():
			dict_fp['cache-control'] = dict_headers['cache-control']
		if 'alternate-protocol' in dict_headers.keys():
			dict_fp['alternate-protocol'] = dict_headers['alternate-protocol']
	except:
		pass
	return dict_fp

def createDbSession():
	engine = create_engine('sqlite:///domain.db')
	Base.metadata.create_all(engine)
	Base.metadata.bind = engine
	DBSession = sessionmaker(bind=engine)
	session = DBSession()
	session.configure(bind=engine)
	return session


def insertIntoDB(session, whois):
	try:
		geoipwhois= DomainInfo(domain = whois['domain'], ip = whois['ip'], whois=str(whois), loc=whois['lat']+","+whois['lon'], fp=str(whois['fp']))
		session.add(geoipwhois)
	except Exception as e:
		print "Exception in inserting"
		pass
	
def makeKml(domain, lat, lon, action, file_kml):
	if action == "start":
		file_kml.write("<?xml version='1.0' encoding='UTF-8'?><kml xmlns='http://www.opengis.net/kml/2.2'><Document>")
	elif action == "placemarker":
		file_kml.write(
		"<Placemark>"+
		"<name>"+domain+"</name>"+
		"<Point><coordinates>+"+lon+","+lat+"</coordinates></Point>"+
		"</Placemark>")
	elif action == "end":
		file_kml.write("</Document></kml>")
		file_kml.close()
	
	
def getListUrls(url):
	page = urllib.urlopen(url).read()
	list_urls = urllib.urlopen(url).readlines()
	re_domain = '(\w+\.\w+?)\/'
	list_domains = re.findall(re_domain, page)
	return list_domains, list_urls

def getIP(domain):
	try:
		ip = subprocess.check_output(["nslookup", domain]).split("\n")[5].split(":")[1].strip()
	except:
		ip = ""	
	return ip

def getWhoIs(list_domains, domain):
	try:
		data = pythonwhois.get_whois(domain)
		list_domains.remove(domain)
	except:
		data = ""
	return list_domains, data

if __name__ == "__main__":
	url = "http://isis.poly.edu/~marcbudofsky/cs6963-spring2015/URLs"
	main(url)
