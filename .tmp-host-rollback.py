#!/usr/bin/env python3
import json, ssl, urllib.request
ctx=ssl._create_unverified_context()
def call(m,p,b=None,t=None):
 r=urllib.request.Request('https://127.0.0.1'+p,data=None if b is None else json.dumps(b).encode(),method=m);r.add_header('Content-Type','application/json')
 if t:r.add_header('Authorization','Bearer '+t)
 with urllib.request.urlopen(r,context=ctx,timeout=30) as x:return json.loads(x.read().decode())
t=call('POST','/api/v1/auth/login',{'username':'admin','password':'AdminTest2!'})['data']['token']
for item in call('GET','/api/v1/response/actions',t=t)['data']['items']:
 if item.get('action')=='isolate_host' and item.get('status')=='executed':
  print(call('POST',f"/api/v1/response/actions/{item['id']}/rollback",{},t=t)['data'])
