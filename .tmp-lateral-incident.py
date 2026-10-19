#!/usr/bin/env python3
import json, ssl, urllib.request
ctx=ssl._create_unverified_context()
def call(m,p,b=None,t=None):
 r=urllib.request.Request('https://127.0.0.1'+p,data=None if b is None else json.dumps(b).encode(),method=m);r.add_header('Content-Type','application/json')
 if t:r.add_header('Authorization','Bearer '+t)
 with urllib.request.urlopen(r,context=ctx,timeout=30) as x:return json.loads(x.read().decode())
t=call('POST','/api/v1/auth/login',{'username':'admin','password':'AdminTest2!'})['data']['token']
data=call('GET','/api/v1/incidents?limit=30',t=t)
for item in data.get('data',{}).get('items',[]):
 txt=json.dumps(item,ensure_ascii=False)
 if 'lateral' in txt:
  print(json.dumps({k:item.get(k) for k in ('id','entity','victim','stages','stage_count','event_count','summary','severity')},ensure_ascii=False))
