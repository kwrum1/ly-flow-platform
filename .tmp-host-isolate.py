#!/usr/bin/env python3
import json, ssl, urllib.request
ctx=ssl._create_unverified_context()
def call(m,p,b=None,t=None):
 r=urllib.request.Request('https://127.0.0.1'+p,data=None if b is None else json.dumps(b).encode(),method=m);r.add_header('Content-Type','application/json')
 if t:r.add_header('Authorization','Bearer '+t)
 with urllib.request.urlopen(r,context=ctx,timeout=30) as x:return json.loads(x.read().decode())
admin=call('POST','/api/v1/auth/login',{'username':'admin','password':'AdminTest2!'})['data']['token']
approver=call('POST','/api/v1/auth/login',{'username':'approver','password':'ApproverTest1!'})['data']['token']
out=call('POST','/api/v1/response/actions',{'incident_id':'host-isolation-acceptance','agent_id':'g5-real-agent','action':'isolate_host','target':'lyflow-test','reason':'safe host isolation acceptance','ttl_seconds':300},t=admin)
rec=out['data']; print('create',rec['id'],rec['status'])
out=call('POST',f"/api/v1/response/actions/{rec['id']}/approve",{},t=approver)
print('approve',out['data']['status'])
print(rec['id'])
