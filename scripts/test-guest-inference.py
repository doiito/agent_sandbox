#!/usr/bin/env python3
"""Actual guest Python module -> fixed local proxy -> root/service/TLS model.

The host bridge and optional C ABI shim are fixtures, not a running guest VM.
"""
import ctypes
import json
from pathlib import Path
import re
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'guest-sdk/python'))
import remote_infer as sdk
import sandbox

config = json.loads(Path(sys.argv[1]).read_text())
mode = sys.argv[2]
identity = lambda n: f'{n:024x}'
def check(name, value):
    assert value, name
    print('PASS '+mode+' '+name, flush=True)
def wait(action):
    deadline=time.monotonic()+5
    while True:
        result=action()
        if result:return result
        assert time.monotonic()<deadline,'bill observation timed out'
        time.sleep(.02)
def entry(number):
    return next((row for row in sdk.bill()['invocations'] if row['id']==identity(number)),{})

policy=sdk.policy()
check('fixed-route-redacted-policy',policy['endpoints'][0]['name']=='model' and 'url' not in json.dumps(policy) and 'credential' not in json.dumps(policy))
initial=sdk.bill()
check('root-logical-task',initial['task_id']==config['task_id'] and not initial['invocations'] and initial['vm_id']!=initial['task_id'])
result=sandbox.ml.invoke('model',{'query':'hi'},invocation_id=identity(1))
check('known-id-exact-integer-money',result.task_id==config['task_id'] and result.invocation_id==identity(1) and result.data=={'answer':'ok'} and isinstance(result.invocation['settled_units'],str) and int(result.invocation['settled_units'])>2**53)
try:sdk.invoke('model',{},invocation_id=identity(1))
except sdk.InferenceError as error:check('duplicate-id-no-replay',error.code=='inference_replay' and error.invocation_id==identity(1) and error.delivery_unknown)
else:raise AssertionError('duplicate succeeded')
try:sdk.invoke('other',{},invocation_id=identity(10))
except sdk.InferenceError as error:check('alias-denied-before-post',not error.delivery_unknown)
else:raise AssertionError('unknown alias succeeded')
for value in [float('nan'),2**53,{'bad':object()}]:
    try:sdk.invoke('model',value,invocation_id=identity(10))
    except sdk.InferenceError as error:assert not error.delivery_unknown and error.invocation_id==identity(10)
    else:raise AssertionError('invalid payload succeeded')
check('unsafe-json-denied-before-post',True)
generated=sdk.invoke('model',{})
check('generated-id-retained',re.fullmatch('[0-9a-f]{24}',generated.invocation_id) is not None and generated.invocation['id']==generated.invocation_id)
large=sdk.invoke('model',{'mode':'unicode'},invocation_id=identity(3))
check('maximum-UTF8-response-through-root-relay',large.data['text']=='\u2028'*config['unicode_count'] and large.invocation['output_bytes']<=512<<10)
errors=[]
def pending():
    try:sdk.invoke('model',{'mode':'pending'},invocation_id=identity(2),request_timeout=.8)
    except sdk.InferenceError as error:errors.append(error)
thread=threading.Thread(target=pending)
thread.start()
wait(lambda:Path(config['pending_marker']).exists())
check('pending-bill-is-observable',entry(2).get('state')=='reserved')
thread.join(3)
assert not thread.is_alive() and len(errors)==1
terminal=wait(lambda: row if (row:=entry(2)).get('state')=='uncertain' else None)
check('absolute-timeout-known-id-held-budget',errors[0].invocation_id==identity(2) and errors[0].delivery_unknown and terminal['settled_units']=='0' and int(terminal['reserved_units'])>0)
final=sdk.bill()
check('all-four-attempts-durably-accounted',len(final['invocations'])==4 and sum(row['state']=='succeeded' for row in final['invocations'])==3 and int(final['held_units'])>0)
if mode=='python-osv-abi':
    library=ctypes.CDLL(None)
    check('actual-ctypes-ABI-partial-I/O-no-half-close',library.osv_test_connects()>4 and library.osv_test_sends()>library.osv_test_connects() and library.osv_test_recvs()>library.osv_test_connects() and library.osv_test_interruptions()>=2 and library.osv_test_shutdowns()==0)
