#!/usr/bin/env python3
import json, ssl, urllib.request
ctx=ssl._create_unverified_context()
def call(m,p,b=None,t=None):
 r=urllib.request.Request('https://127.0.0.1'+p,data=None if b is None else json.dumps(b).encode(),method=m);r.add_header('Content-Type','application/json')
 if t:r.add_header('Authorization','Bearer '+t)
 with urllib.request.urlopen(r,context=ctx,timeout=30) as x:return json.loads(x.read().decode())
admin=call('POST','/api/v1/auth/login',{'username':'admin','password':'AdminTest2!'})['data']['token']
approver=call('POST','/api/v1/auth/login',{'username':'approver','password':'ApproverTest1!'})['data']['token']
rec=call('POST','/api/v1/response/actions',{'incident_id':'namespace-acceptance','agent_id':'g5-real-agent','action':'namespace_isolate','target':'lyflow-response-target','reason':'safe container network acceptance','ttl_seconds':300},t=admin)['data']
print('create',rec['id'],rec['status'])
print('approve',call('POST',f"/api/v1/response/actions/{rec['id']}/approve",{},t=approver)['data']['status'])
