import json
import os
import httplib2
import time
'''
return balance of an account
'''
llista = os.listdir('./')
CSV = []
for i in llista:
    if i[0]=='m' or i[0]=='n':
        CSV.append(i)
#print CSV
http = httplib2.Http()
for address in CSV:
    content = http.request("https://api.blockcypher.com/v1/btc/test3/addrs/"+address+"/balance")
#    print content[1]
    data = json.loads(content[1])
    print 'Address:', address
    print 'balance', data['balance']
    time.sleep(1) # to avoid blackmailing
