import re
import requests
import json
import argparse
import streamlit as st
import time
import streamlit as st
import pandas as pd
import plotly.express as px
from geopy.geocoders import Nominatim
import urllib.request
import os.path, time
from bs4 import BeautifulSoup
import folium
import plotly.graph_objects as go
from PIL import Image
from IPython.display import HTML
from OTXv2 import OTXv2
import IndicatorTypes
import argparse
import os
import time
import pandas as pd
import numpy as np
import json
import csv
from io import StringIO
import pulsedive





# Keys of API are here
file=open("keys.txt",'r')
row = file.readlines()


try:
    os.remove("ipdb.json")
    os.remove("ipdb_main.json")
    os.remove("ipdb_reports.json")
    os.remove("otxone.json")
    os.remove("vt.json")

except:
    pass


class get_stats: # The objective of this class its collect the IP that will be investigated and further check if its valid by finally saving it

    def __init__(self):
        pass


    def usr_inp(self):  # Get user input and store it for future use

        self.ip_dc = list() # List IP contains unchecked
        self.cl_ip = list() # After regex
        self.scl_ip = list() # Last step to clean IP
        for i in range(1) :
            self.fll = open("ipi.txt")

            tget_ip = self.fll.read()
            self.ip_dc.append(tget_ip)
            self.testip()

        self.save_ip()



    def testip(self): # Test user input to verity if its a good IP


        for i in self.ip_dc :
            x = re.compile (r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
            findIP = re.match(x , i)



            if findIP :

                self.cl_ip.append(findIP)

                for clip in self.cl_ip:
                    clip = self.cl_ip[0].group(0)


                    for part in clip.split("."):
                        if int(part) < 0 or int(part) > 255:
                            print("IP address {} is not valid".format(clip))
                            return False

                    self.scl_ip.append(clip)
                    print("IP address {} is valid".format(clip))

            else:
                print("No valid  information was putten ")


    def save_ip(self):

        f = open("ips.txt", "w")
        for everyip in self.scl_ip:
            f.write(everyip)
        f.close()




class ipdb_query:

    def __init__(self , key , ip):
        self.apikey = key
        self.ipkey = ip


    def sv_json(self):

        f = open("ipdb.json", "w")

        f.write(self.ind_j)
        f.close()

    def get_cat(self , x):
        return {
            0: 'BLANK',
            3: 'Fraud_Orders',
            4: 'DDoS_Attack',
            5: 'FTP_Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open_Proxy',
            10: 'Web_Spam',
            11: 'Email_Spam',
            12: 'Blog_Spam',
            13: 'VPN IP',
            14: 'Port_Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute_Force',
            19: 'Bad_Web_Bot',
            20: 'Exploited_Host',
            21: 'Web_App_Attack',
            22: 'SSH',
            23: 'IoT_Targeted',
        }.get(
            x,
            'UNK CAT, ***REPORT TO MAINTAINER***OPEN AN ISSUE ON GITHUB w/ IP***')

    def get_ipdb(self):


        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'




        querystring = {
            'ipAddress': self.ipkey,
            'maxAgeInDays': '30',
            'verbose': ''
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.apikey,
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        # Formatted output
        decodedResponse = json.loads(response.text)

        # Formatted output
        time.sleep(20)

        for report in decodedResponse['data']['reports']:
            tmp_catergory = []
            category = report['categories']
            for cat in category:
                tmp_catergory.append(self.get_cat(cat))
            report['categories'] = tmp_catergory
            self.ind_j = json.dumps(decodedResponse, sort_keys=True, indent=4 , separators = (", ", ":"))

        return self.ind_j


    def open_it(self ):
        self.q_ip = list()
        f = open("ips.txt", "r")




        for ip in f:
            ip = str(ip)
            self.q_ip.append(ip)

        for any in self.q_ip:

            f = open("ipdb.json", "w")
            a = self.get_ipdb(any)
            f.write(a)
            f.close()

try:

    q_ip = list()
    f = open("ips.txt", "r")

    for ip in f:
        ip = str(ip)
        q_ip.append(ip)



    star = get_stats()
    star.usr_inp()
    sstar = ipdb_query(str(row[1].strip("\n")), str(q_ip[0]) )
    a = sstar.get_ipdb()
    for i in range(1):
        t1 = open("ipdb.json", "w+")

        t1.write(a)
        t1.close()
        pass

except:
    pass

###################################################
class Virustotl():

    def __init__(self , key):
        self.host = "www.virustotal.com"
        self.base = "https://www.virustotal.com/vtapi/v2/"
        self.apikey = key

    def ipReport(self, rsc):

        base = self.base + 'ip-address/report'
        parameters = {"ip":rsc, "apikey":self.apikey}
        r = requests.get(base, params=parameters)
        resp = r.json()
        print(resp)
        resp1 = json.dumps(resp , indent = 4, sort_keys=True)
        print(resp1)
        p = re.compile('(?<!\\\\)\'')
        str1 = p.sub('\"', resp1)
        loaded_rr = json.loads(str1)
        print(loaded_rr)
        return loaded_rr


a =  Virustotl(str(row[0].strip("\n")))



b = a.ipReport(str(q_ip[0]))



d9 = pd.DataFrame.from_dict(dict(b), orient='Index')
d9.to_csv("vt_i.csv")


#######################################################


def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results


def ip(otx, ip):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])

    return alerts



time.sleep(1)



# store OTX API key in environment variable OTX_API_KEY
API_KEY = os.getenv(str(row[2].strip("\n")))

otx = OTXv2(API_KEY)
# print(str(otx.get_indicator_details_full(IndicatorTypes.IPv4, ["113.215.181.54"])))

data = list()

alerts = ip(otx, q_ip[0])
if len(alerts) > 0:
    for i in alerts :
        data.append(i)
else:
    data.append("Nothing found on OTX")



daf = pd.DataFrame(data)
daf.to_json("otxone.json")

key_r = str(row[3].strip("\n"))
ip_r  = str(q_ip[0])
url_f ='https://ipqualityscore.com/api/json/ip/'+ key_r + '/'+ip_r


res = requests.get(url_f)

resp = res.json()
resp1 = json.dumps(resp)
loaded_r = json.loads(resp1)

df1 = pd.DataFrame.from_dict(loaded_r, orient='Index')

df1.to_csv(r'vpn_check.csv')





with open("ipdb.json", "r") as read_file:  # Open our jason file
    data = json.load(read_file)
    final_data = data['data']


##################################################





def get_pul_dive(key , ip):
    pud = pulsedive.Pulsedive(key)
    ind = pud.indicator(value= ip)
    pd10 = pd.DataFrame.from_dict(dict(ind), orient='Index')
    pd10.to_csv("pulsedv.csv")

key_pul = str(row[4].strip("\n"))

get_pul_dive(key_pul ,str(ip_r))






######################################################
#Clean Up json

def clean_json_now(data):


    formatted_json = json.dumps(
      data,
      indent = 4,
      separators = (", ", ":"),
      sort_keys = True, )


    fformated_json = json.loads(formatted_json)

    return fformated_json

def sv_json(data ,name):
    f = open(name , "w")

    f.write(data)
    f.close()

def json_opp(namej):
    with open(namej) as json_file:
        data_s = json.load(json_file)
    return data_s


def js_to_csv(namecsv , outcsv):
    df = pd.read_json(namecsv)

    df.to_csv(outcsv, index=None)





def clean_text(text):
    text = text.lower()
    text = re.sub('\[.*?\]', '', text)

    return text

first_clean = clean_json_now(final_data) # Here i will query just the reports present and save on Json
first_clean_report = first_clean['reports']

json_string = json.dumps(first_clean_report)


sv_json(json_string, "ipdb_reports.json") # Save json



del final_data['reports'] # Than delete the reports and present just the main data
json_string2 = json.dumps(final_data)
sv_json(json_string2 , "ipdb_main.json") # Save json
#
##########################################################
#Save all the files parsed from jason to Csv


with open("ipdb_reports.json") as json_file:
    data_ip = json.load(json_file)
    j_data_ip = json.dumps(data_ip)





df9 = pd.read_json(StringIO(j_data_ip))
df9.to_csv(r'ip_rep.csv', index=None)

with open("ipdb_main.json") as json_file:
    data_mn = json.load(json_file)


df8 = pd.DataFrame.from_dict(data_mn , orient='Index')
df8.to_csv(r'ip_main.csv')

########################################################
df = pd.read_csv("ip_rep.csv")


df_new = (df.set_axis(['Categories', 'Comment', 'Date reported', 'Country code', 'Country Name',  'User ID'], axis=1))
df_new['Date reported'] = df_new['Date reported'].str[:10]

df_new.to_csv(r'ip_rep.csv')