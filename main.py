
import socket, time, uuid, re
from typing import List
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import concurrent.futures
try:
    from Crypto.Cipher import DES
    HAS_CRYPTO=True
except:
    HAS_CRYPTO=False

app=FastAPI(title="SUNGATE TITAN API v7 MULTI-METHOD")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
jobs={}

class CheckRequest(BaseModel):
    lines: List[str]
    timeout: int=5
    delay: int=0

def parse_c_line(line:str):
    line=line.strip()
    if not line: return None
    clean=re.sub(r'^C:\s*','',line,flags=re.I).strip()
    parts=clean.split()
    if len(parts)<4: return None
    try:
        host=parts[0];port=int(parts[1]);user=parts[2];pwd=parts[3]
        if not (1 <= port <= 65535): return None
        return (host,port,user,pwd,line)
    except:
        return None

def check_one_method(host,port,user,pwd,method,timeout):
    sock=None
    start=time.time()
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host,port))
        sock.settimeout(1.5)
        seed=b""
        try:
            seed=sock.recv(1024)
        except:
            seed=b""
        if method==1:
            user_payload=user.encode()[:20].ljust(20,b'\0')
            pwd_payload=pwd.encode()+b'\0'
            sock.settimeout(timeout)
            sock.sendall(user_payload)
            try:
                sock.settimeout(0.8)
                _=sock.recv(1024)
            except:
                pass
            sock.sendall(pwd_payload)
        elif method==2:
            payload=f"{user}\0{pwd}\0".encode()
            sock.settimeout(timeout)
            sock.sendall(payload)
        else:
            payload=user.encode()[:20].ljust(20,b'\0')+pwd.encode()[:20].ljust(20,b'\0')+b"CCcam\x002.3.0\0"
            sock.settimeout(timeout)
            sock.sendall(payload)
        time.sleep(2.2)
        try:
            sock.setblocking(False)
            try:
                data=sock.recv(4096)
                if len(data)==0:
                    return False,seed,data,int((time.time()-start)*1000),f"m{method}: closed quickly (wrong pass) seed={len(seed)}b"
                else:
                    return True,seed,data,int((time.time()-start)*1000),f"m{method}: got {len(data)}b -> WORKING"
            except BlockingIOError:
                return True,seed,b"OPEN",int((time.time()-start)*1000),f"m{method}: still open 2.2s -> WORKING seed={len(seed)}b"
        finally:
            try:
                sock.setblocking(True)
            except:
                pass
    except Exception as e:
        return False,b"",b"",int((time.time()-start)*1000),f"m{method} err {str(e)[:80]}"
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def try_login_v7(host,port,user,pwd,timeout=5):
    last=(False,b"",b"",0,"no attempt")
    for m in [1,2,3]:
        is_open,seed,resp,elapsed,info=check_one_method(host,port,user,pwd,m,timeout)
        last=(is_open,resp,seed,elapsed,info)
        if is_open:
            return True,resp,seed,elapsed,f"WORKING via m{m}: {info}"
        import time as _t
        _t.sleep(0.3)
    return False,last[1],last[2],last[3],f"All 3 methods closed -> AUTH_FAILED | last: {last[4]}"

def check_real(host,port,user,pwd,orig,timeout=5):
    is_open,resp,seed,elapsed,info=try_login_v7(host,port,user,pwd,timeout)
    if is_open:
        return {"line":orig,"cline":orig,"ok":True,"working":True,"status":"working","response_time":elapsed,"first_len":len(seed),"resp_len":len(resp) if isinstance(resp,bytes) else 0,"info":info}
    else:
        st="auth_failed"
        if "refused" in info.lower(): st="closed"
        return {"line":orig,"cline":orig,"ok":False,"working":False,"status":st,"response_time":elapsed,"error":info,"first_len":len(seed),"resp_len":len(resp) if isinstance(resp,bytes) else 0}

def check_batch(lines,timeout=5):
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures={}
        for line in lines:
            parsed=parse_c_line(line)
            if not parsed:
                results.append({"line":line,"cline":line,"ok":False,"working":False,"status":"invalid_format","error":"parse failed"})
            else:
                host,port,user,pwd,orig=parsed
                fut=executor.submit(check_real,host,port,user,pwd,orig,timeout)
                futures[fut]=orig
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"line":futures[fut],"ok":False,"status":"error","error":str(e)})
    ordered=[]
    for line in lines:
        f=next((r for r in results if r.get("line")==line),None)
        if f: ordered.append(f)
    for r in results:
        if r.get("line") not in [o.get("line") for o in ordered]:
            ordered.append(r)
    return ordered

@app.get("/")
def root():
    return {"status":"online","version":"v7-MULTI-METHOD","service":"SUNGATE TITAN API v7 - Real Auth","endpoints":["/check-cccam-sync","/debug-single"],"crypto":HAS_CRYPTO}

@app.get("/health")
def health():
    return {"ok":True,"crypto":HAS_CRYPTO,"version":"v7"}

@app.post("/check-cccam-sync")
def check_sync(req:CheckRequest):
    return {"results":check_batch(req.lines,timeout=req.timeout),"count":len(req.lines)}

@app.post("/check-cccam")
def check_async(req:CheckRequest,background_tasks:BackgroundTasks):
    job_id=str(uuid.uuid4())[:8]
    jobs[job_id]={"status":"running","results":[],"created":time.time()}
    def run_job():
        res=check_batch(req.lines,timeout=req.timeout)
        jobs[job_id]={"status":"completed","results":res,"done":True}
    background_tasks.add_task(run_job)
    return {"job_id":job_id,"id":job_id,"status":"queued"}

@app.get("/cccam-jobs/{job_id}")
def get_job(job_id:str):
    return jobs.get(job_id,{"status":"not_found"})

@app.post("/debug-single")
def debug_single(req:CheckRequest):
    if not req.lines:
        return {"error":"no lines"}
    line=req.lines[0]
    parsed=parse_c_line(line)
    if not parsed:
        return {"error":"parse failed"}
    host,port,user,pwd,orig=parsed
    details=[]
    for m in [1,2,3]:
        is_open,seed,resp,elapsed,info=check_one_method(host,port,user,pwd,m,req.timeout)
        details.append({"method":m,"is_open":is_open,"seed_len":len(seed),"seed_hex":seed[:50].hex() if seed else "","resp_len":len(resp) if isinstance(resp,bytes) else 0,"resp_data":str(resp[:100]) if isinstance(resp,bytes) else str(resp),"elapsed":elapsed,"info":info})
        import time as _t
        _t.sleep(0.2)
    any_open=any(d["is_open"] for d in details)
    best=next((d for d in details if d["is_open"]), details[-1] if details else None)
    return {
        "line":orig,
        "is_open_after_login":any_open,
        "seed_hex":best["seed_hex"] if best else "",
        "seed_len":best["seed_len"] if best else 0,
        "resp_len":best["resp_len"] if best else 0,
        "resp_data":best["resp_data"] if best else "",
        "elapsed_ms":best["elapsed"] if best else 0,
        "info":best["info"] if best else "",
        "interpretation":"WORKING" if any_open else "AUTH_FAILED - all 3 methods closed",
        "details":details,
        "any_working":any_open,
        "version":"v7"
    }
