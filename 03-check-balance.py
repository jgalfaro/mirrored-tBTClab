import json
import os
import httplib2
import time
'''
return balance of an account
'''
MyList = os.listdir('./')
CSV = []
for i in MyList:
    #tBTC addresses starting by magic word 'm' or 'n'
    if i[0]=='m' or i[0]=='n':
        CSV.append(i)

http = httplib2.Http()
for address in CSV:
    content = http.request("https://api.blockcypher.com/v1/btc/test3/addrs/"+address+"/balance")
    data = json.loads(content[1])
    print('Address:', address)
    print('balance', data['balance'])
    time.sleep(1) # to avoid getting blacklisted
