import json

import httplib2

http = httplib2.Http()
content = http.request("http://tbtc.blockr.io/api/v1/address/balance/mzCt5tnfTRYqGHVPVVpAdgzwVHDNoBMC8b")[1]

print(content.decode())

alive_reponse = json.loads(content)

print alive_reponse

print 'balance' ,alive_reponse['data']['balance']
