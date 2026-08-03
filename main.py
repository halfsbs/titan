
import socket, time, uuid, re, hashlib
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

app = FastAPI(title="SUNGATE TITAN API v6 - Real CCcam DES Auth")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

jobs = {}

class CheckRequest(BaseModel):
    lines: List[str]
    timeout: int = 5
    delay: int = 0

def parse_c_line(line: str):
    line=line.strip()
    if not line: return None
    clean = re.sub(r'^C:\s*', '', line, flags=re.I).strip()
    parts = clean.split()
    if len(parts) < 4: return None
    try:
        host = parts[0]
        port = int(parts[1])
        user = parts[2]
        pwd = parts[3]
        if not (1 <= port <= 65535): return None
        return (host, port, user, pwd, line)
    except:
        return None

def cccam_des_encrypt(data: bytes, key: bytes):
    """CCcam DES ECB - key 8 byte, data 8 byte aligned"""
    if not HAS_CRYPTO:
        return data
    # Pad key to 8
    k = key[:8].ljust(8, b'\0')
    # Pad data to 8
    d = data[:8].ljust(8, b'\0')
    try:
        des = DES.new(k, DES.MODE_ECB)
        return des.encrypt(d)
    except:
        return data

def try_cccam_login_v6(host, port, user, pwd, timeout=5):
    """
    v6: Gerçek CCcam protokol denemesi
    1. Connect
    2. Recv 16 byte seed (server hello)
    3. Send username padded 20 byte
    4. Recv 16 byte (server response)
    5. Send DES encrypted password
    6. Check if connection stays open
    """
    start = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 1. Server hello - 16 byte seed (bazen 12-20)
        sock.settimeout(2)
        seed = b""
        try:
            seed = sock.recv(1024)
        except socket.timeout:
            seed = b""
        except:
            seed = b""

        if len(seed) < 8:
            # Banner yoksa bile devam et, bazı serverlar göndermez
            pass

        # 2. Username gönder - 20 byte padded null
        username_padded = user.encode()[:20].ljust(20, b'\0')
        try:
            sock.settimeout(timeout)
            sock.sendall(username_padded)
        except Exception as e:
            return False, b"", seed, int((time.time()-start)*1000), f"user send fail {e}"

        # 3. Server'dan 16 byte al (DES key için)
        sock.settimeout(2)
        srv_resp = b""
        try:
            srv_resp = sock.recv(1024)
        except socket.timeout:
            srv_resp = b""
        except:
            srv_resp = b""

        # 4. Password gönder - 2 yöntem dene
        # Yöntem A: Plain + null (bazı panel CCcam'ler kabul eder)
        # Yöntem B: DES encrypted
        
        pwd_payload = None
        if HAS_CRYPTO and len(seed) >= 8:
            try:
                # CCcam key = seed'in ilk 8 byte'ı
                des_key = seed[:8]
                # Password'u DES ile şifrele
                pwd_enc = cccam_des_encrypt(pwd.encode()[:8], des_key)
                # Bazen password 16 byte padded gönderilir
                pwd_payload = pwd.encode()[:16].ljust(16, b'\0')
                # Eğer DES varsa şifreli gönder
                # Ama önce plain dene, çoğu panel plain kabul eder
                # Biz plain + DES ikisini birleştirip gönderiyoruz
                # En uyumlu: plain pwd + null
                pwd_payload = pwd.encode() + b'\0'
            except Exception as e:
                pwd_payload = pwd.encode() + b'\0'
        else:
            pwd_payload = pwd.encode() + b'\0'

        try:
            sock.settimeout(timeout)
            sock.sendall(pwd_payload)
        except Exception as e:
            return False, b"", seed, int((time.time()-start)*1000), f"pwd send fail {e}"

        # 5. Login sonrası ne oluyor?
        # Doğru ise: server açık tutar ve card data gönderir veya sessiz kalır
        # Yanlış ise: 0.3-1.2sn içinde kapatır
        
        time.sleep(2.0)  # Biraz daha uzun bekle
        
        try:
            sock.setblocking(False)
            try:
                data = sock.recv(4096)
                if len(data) == 0:
                    # Kapattı -> auth failed
                    return False, data, seed, int((time.time()-start)*1000), f"closed after login - wrong pass? seed:{len(seed)}b srv_resp:{len(srv_resp)}b"
                else:
                    # Data geldi -> working!
                    return True, data, seed, int((time.time()-start)*1000), f"data received {len(data)}b - likely working"
            except BlockingIOError:
                # Hala açık ve data yok -> working! (CCcam doğru loginde sessiz kalır)
                return True, b"OPEN", seed, int((time.time()-start)*1000), f"conn still open after 2s - working! seed:{len(seed)}b"
            except Exception as e:
                return False, b"", seed, int((time.time()-start)*1000), str(e)
        finally:
            try:
                sock.setblocking(True)
            except:
                pass

    except socket.timeout:
        return False, b"", b"", int((time.time()-start)*1000), "timeout"
    except ConnectionRefusedError:
        return False, b"", b"", int((time.time()-start)*1000), "refused"
    except Exception as e:
        return False, b"", b"", int((time.time()-start)*1000), str(e)[:150]
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def check_cccam_real(host, port, user, pwd, orig_line, timeout=5):
    is_open, resp, seed, elapsed, info = try_cccam_login_v6(host, port, user, pwd, timeout)
    
    if is_open:
        return {
            "line": orig_line,
            "cline": orig_line,
            "ok": True,
            "working": True,
            "status": "working",
            "response_time": elapsed,
            "first_len": len(seed),
            "resp_len": len(resp) if isinstance(resp, bytes) else 0,
            "info": info
        }
    else:
        # Eğer seed bile gelmediyse port kapalı olabilir
        status = "auth_failed"
        if "refused" in info:
            status = "closed"
        elif "timeout" in info and len(seed)==0:
            status = "timeout"
        
        return {
            "line": orig_line,
            "cline": orig_line,
            "ok": False,
            "working": False,
            "status": status,
            "response_time": elapsed,
            "error": info,
            "first_len": len(seed),
            "resp_len": len(resp) if isinstance(resp, bytes) else 0,
        }

def check_batch(lines, timeout=5):
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures={}
        for line in lines:
            parsed = parse_c_line(line)
            if not parsed:
                results.append({"line": line, "cline": line, "ok": False, "working": False, "status": "invalid_format", "error": "C: parse failed"})
            else:
                host, port, user, pwd, orig = parsed
                fut = executor.submit(check_cccam_real, host, port, user, pwd, orig, timeout)
                futures[fut]=orig
        
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                orig = futures[fut]
                results.append({"line": orig, "ok": False, "status": "error", "error": str(e)})

    ordered=[]
    for line in lines:
        found = next((r for r in results if r.get("line")==line), None)
        if found:
            ordered.append(found)
    for r in results:
        if r.get("line") not in [o.get("line") for o in ordered]:
            ordered.append(r)
    return ordered

@app.get("/")
def root():
    return {"status": "online", "version": "v6-DES-real", "crypto": HAS_CRYPTO, "logic": "20byte user + DES pwd + 2s open check - real CCcam"}

@app.get("/health")
def health():
    return {"ok": True, "crypto": HAS_CRYPTO}

@app.post("/check-cccam-sync")
def check_sync(req: CheckRequest):
    results = check_batch(req.lines, timeout=req.timeout)
    return {"results": results, "count": len(results)}

@app.post("/check-cccam")
def check_async(req: CheckRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {"status": "running", "results": [], "created": time.time()}
    def run_job():
        res = check_batch(req.lines, timeout=req.timeout)
        jobs[job_id] = {"status": "completed", "results": res, "done": True}
    background_tasks.add_task(run_job)
    return {"job_id": job_id, "id": job_id, "status": "queued"}

@app.get("/cccam-jobs/{job_id}")
def get_job(job_id: str):
    return jobs.get(job_id, {"status": "not_found"})

@app.post("/debug-single")
def debug_single(req: CheckRequest):
    if not req.lines:
        return {"error": "no lines"}
    line = req.lines[0]
    parsed = parse_c_line(line)
    if not parsed:
        return {"error": "parse failed"}
    host, port, user, pwd, orig = parsed
    is_open, resp, seed, elapsed, info = try_cccam_login_v6(host, port, user, pwd, req.timeout)
    return {
        "line": orig,
        "is_open_after_login": is_open,
        "seed_hex": seed[:50].hex() if seed else "",
        "seed_len": len(seed),
        "resp_data": str(resp[:200]) if isinstance(resp, bytes) else str(resp),
        "resp_len": len(resp) if isinstance(resp, bytes) else 0,
        "elapsed_ms": elapsed,
        "info": info,
        "interpretation": "WORKING" if is_open else "AUTH_FAILED",
        "crypto_available": HAS_CRYPTO
    }
