import argparse
import os.path
import csv
import socket
import sys
import requests
import json
import base64
import ipwhois
import pprint

# Script to parse a list of IPs and gather information from X-Force, GeoIP and Whois
# Created by Thiago Lahr in 2016

def queryGeoIP(ip):
    
    try:
        url = 'http://api.hackertarget.com/geoip/?q=' + ip
        response = requests.get(url, params = '', timeout = 5)
    except requests.exceptions.Timeout:
        print(u'GeoIP Error: Timeout')
    except requests.exceptions.HTTPError as e:
        print(u'GeoIP Error: %s' % e.message)
    except requests.exceptions.ConnectionError:
        print(u'GeoIP Error: URL (' + url + ') not found')
    else:
        queryresult = response.text
    
    try:
        lines = queryresult.split('\n')
        country = lines[1].split(':')[-1:]
        state = lines[2].split(':')[-1:]
        city = lines[3].split(':')[-1:]
        latitude = lines[4].split(':')[-1:]
        longitude = lines[5].split(':')[-1:]
        
        returnvalue = [
            country[0].replace('\n', ' ').strip(),
            state[0].replace('\n', ' ').strip(),
            city[0].replace('\n', ' ').strip(),
            latitude[0].replace('\n', ' ').strip(),
            longitude[0].replace('\n', ' ').strip()
        ]
    except:
        returnvalue = [
            "",
            "",
            "",
            "",
            ""
        ]
        
    return returnvalue


def queryXFE(ip):
# Please obtain an API key from XFE and add it to the fields bellow. doc: https://api.xforce.ibmcloud.com/doc/
    apikey = "xxxx-xxxxx-xxx-xxxx-xxx"
    apipassword = "xxxx-xxxx-xxxxx-xxxx-xxx"
    
    try:
        token = base64.b64encode(apikey + ":" + apipassword)
        headers = {"Authorization": "Basic " + token, "Accept": "application/json"}
        url = 'https://api.xforce.ibmcloud.com:443/ipr/' + ip
        response = requests.get(url, params='', headers = headers, timeout = 10)
    except requests.exceptions.Timeout:
        print(u'XFE Error: Timeout')
    except requests.exceptions.HTTPError as e:
        print(u'XFE Error: %s' % e.message)
    except requests.exceptions.ConnectionError:
        print(u'XFE Error: URL (' + url + ') not found')
    else:
        queryresult = response.json()
    
    categorydescriptions = ""
    try:
        if len(queryresult['categoryDescriptions']) > 0:
            for key, value in queryresult['categoryDescriptions'].items():
                categorydescriptions = categorydescriptions + key + ': ' + value + ' | '

        returnvalue = [
            queryresult['geo']['country'].replace('\n', ' '),
            queryresult['geo']['countrycode'].replace('\n', ' '),
            categorydescriptions[:-3].replace('\n', ' '),
            queryresult['reason'].replace('\n', ' '),
            queryresult['reasonDescription'].replace('\n', ' '),
            queryresult['score']
        ]
    except:
        returnvalue = [
            "",
            "",
            "",
            "", 
            "",
            ""
        ]
            
    return returnvalue


def queryIPWhois(ip):

    try:
        query = ipwhois.IPWhois(ip)
        queryresult = query.lookup_whois()
    except:
        pass
        
    try:
        asn = queryresult['asn'].replace('\n', ' ') if not queryresult['asn'] == None else ""
        asnregistry = queryresult['asn_registry'].replace('\n', ' ') if not queryresult['asn_registry'] == None else ""
        netsaddress = queryresult['nets'][0]['address'].replace('\n', ' ') if not queryresult['nets'][0]['address'] == None else ""
        netscidr = queryresult['nets'][0]['cidr'].replace('\n', ' ') if not queryresult['nets'][0]['cidr'] == None else ""
        netscity = queryresult['nets'][0]['city'].replace('\n', ' ') if not queryresult['nets'][0]['city'] == None else ""
        netscountry = queryresult['nets'][0]['country'].replace('\n', ' ') if not queryresult['nets'][0]['country'] == None else ""
        netsdescription = queryresult['nets'][0]['description'].replace('\n', ' ') if not queryresult['nets'][0]['description'] == None else ""
        netsrange = queryresult['nets'][0]['range'].replace('\n', ' ') if not queryresult['nets'][0]['range'] == None else ""
        
        returnvalue = [
            asn, 
            asnregistry, 
            netsaddress,
            netscidr,
            netscity,
            netscountry,
            netsdescription,
            netsrange
        ]
    except:
        returnvalue = [
            "", 
            "", 
            "", 
            "", 
            "", 
            "", 
            "", 
            ""
        ]
        
    return returnvalue

        
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description = '')
    parser.add_argument('input', help = 'ip or file')
    parser.add_argument('output', help = 'csv file')
    args = parser.parse_args()
    
    iplist = []
    
    if os.path.exists(args.input):
        try:
            inputfile = open(args.input, 'r')
        except IOError as e:
            sys.exit(u'Cannot open input file %s : %s' % (args.input, e.strerror))
        else:
            for line in inputfile:
               iplist.append(line.rstrip())
    
    else:
        iplist.append(args.input.rstrip())
        
    try:
        outputfile = open(args.output, 'w')
        csvheader = [
            'ip',
            'fqdn',
            'whois_asn', 
            'whois_asn_registry', 
            'whois_address', 
            'whois_cidr', 
            'whois_city', 
            'whois_country', 
            'whois_description', 
            'whois_range',
            'xfe_country',
            'xfe_contrycode',
            'xfe_category_descriptions',
            'xfe_reason',
            'xfe_reason_description',
            'xfe_score',
            'geoip_country',
            'geoip_state',
            'geoip_city',
            'geoip_latitude',
            'geoip_longitude'
        ]
        csvwriter = csv.writer(outputfile, delimiter = ',', quotechar = '"', quoting = csv.QUOTE_ALL)
        csvwriter.writerow(csvheader)
    except IOError as e:
        sys.exit(u'Cannot write to the output file %s : %s' % (args.output, e.strerror))

    numberoflines = len(iplist)
    count = 1
    for ip in iplist:
        
        print ('Querying ' + ip + ' (' + str(count) + '/' + str(numberoflines) + ')')
        
        # FQDN
        fqdn = socket.getfqdn(ip)
        
        csvline = [
            ip,
            fqdn
        ]
            
        # whois
        csvline = csvline + queryIPWhois(ip)
            
        # XFE
        csvline = csvline + queryXFE(ip)
        
        # GeoIP
        csvline = csvline + queryGeoIP(ip)
        
        try:
            csvwriter.writerow(csvline)
        except csv.Error as e:
            raise csv.Error(u'Error writing output csv file: %s' % e)

        count += 1
    
    
