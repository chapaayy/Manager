"""Unprivileged outbound-only poller, not a Docker root-agent."""
import json
from pathlib import Path
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HUB=os.environ['XPPN_HUB_URL'].rstrip('/')
ID=os.environ['XPPN_NODE_ID']
TOKEN=os.environ['XPPN_AGENT_TOKEN']
SOCK='/run/xppn-agent/helper.sock'
if not HUB.startswith('https://'):
    raise RuntimeError('Agent refuses non-HTTPS HUB URL')

def rpc(command,payload=None,proof=None):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(1500)
        s.connect(SOCK)
        obj={'command':command,'payload':payload or {}}
        if proof:
            obj['signed']=proof['signed']
            obj['signature']=proof['signature']
        s.sendall((json.dumps(obj,ensure_ascii=False)+'\n').encode())
        data=bytearray()
        while len(data)<300000:
            chunk=s.recv(65536)
            if not chunk:break
            data.extend(chunk)
            if b'\n' in data:break
    result=json.loads(data.partition(b'\n')[0]);
    if not result['ok']:raise RuntimeError(result['error'])
    return result['result']

def request(method,path,payload=None):
    headers={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(f'{HUB}/api/agent/{ID}/{path}',headers=headers,data=data,method=method)
    # urllib verifies TLS CA and hostname by default.
    with urllib.request.urlopen(req,timeout=30) as res:
        return json.loads(res.read(250000))

def relay_progress(job_id, sent):
    path=Path('/run/xppn-agent')/('progress-'+job_id+'.log')
    try:
        with path.open('rb') as f:
            f.seek(sent)
            chunk=f.read(24000)
            position=f.tell()
        for line in chunk.decode(errors='replace').splitlines():
            if line.strip():request('POST','progress',{'job_id':job_id,'message':line[:450]})
        return position
    except FileNotFoundError:return sent
    except Exception as e:
        print('Progress delivery delayed:',type(e).__name__,flush=True)
        return sent

def main():
    last_heartbeat=0
    last_status={}
    with ThreadPoolExecutor(max_workers=1) as worker:
        while True:
            try:
                if time.monotonic()-last_heartbeat>45:
                    last_status=rpc('status')
                    request('POST','heartbeat',{'telemetry':last_status})
                    last_heartbeat=time.monotonic()
                reply=request('GET','next')
                job=reply.get('job')
                if job:
                    work=worker.submit(rpc,job['command'],job.get('payload') or {},job)
                    sent_progress=0
                    next_heartbeat=0
                    while not work.done():
                        sent_progress=relay_progress(job['id'],sent_progress)
                        if time.monotonic()>=next_heartbeat:
                            try:
                                request('POST','heartbeat',{'telemetry':{**last_status,'working':job['command']}})
                            except Exception as e:
                                print('Heartbeat unavailable:',type(e).__name__,flush=True)
                            next_heartbeat=time.monotonic()+15
                        time.sleep(2)
                    sent_progress=relay_progress(job['id'],sent_progress)
                    try:
                        result=work.result()
                        output=json.dumps(result,ensure_ascii=False) if not isinstance(result,str) else result
                        outcome={'job_id':job['id'],'success':True,'output':output[:129000]}
                    except Exception as e:
                        outcome={'job_id':job['id'],'success':False,'output':str(e)[:3000]}
                    request('POST','result',outcome)
                    last_heartbeat=0
            except Exception as e:
                print('Disconnected or command failed:',type(e).__name__,flush=True)
            time.sleep(8)

if __name__=='__main__':main()
