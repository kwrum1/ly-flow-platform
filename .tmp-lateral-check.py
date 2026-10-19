#!/usr/bin/env python3
import json, ssl, urllib.request
ctx=ssl._create_unverified_context()
def call(m,p,b=None,t=None):
 r=urllib.request.Request('https://127.0.0.1'+p,data=None if b is None else json.dumps(b).encode(),method=m);r.add_header('Content-Type','application/json')
 if t:r.add_header('Authorization','Bearer '+t)
 with urllib.request.urlopen(r,context=ctx,timeout=30) as x:return json.loads(x.read().decode())
t=call('POST','/api/v1/auth/login',{'username':'admin','password':'AdminTest2!'})['data']['token']
for q in ['/api/v2/events?limit=50','/api/v1/incidents?limit=20']:
 data=call('GET',q,t=t)
 print('QUERY',q, data.get('data',{}).get('total'))
 text=json.dumps(data,ensure_ascii=False)
 print('lateral', 'lateral.movement' in text, 'lateral_movement' in text)
 if 'lateral' in text:
  for item in data.get('data',{}).get('items',[]):
   if 'lateral' in json.dumps(item,ensure_ascii=False).lower():
    print(json.dumps(item,ensure_ascii=False)[:900])
