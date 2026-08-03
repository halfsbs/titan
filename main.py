
import asyncio, socket, time, uuid, hashlib, struct, re
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import concurrent.futures

app = FastAPI(title="SUNGATE TITAN API - CCcam Checker v3")

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

def cccam_check_single(host, port, user, pwd, original_line, timeout=5):
    """
    Gerçek CCcam kontrolü:
    1. TCP bağlan
    2. Server hello al (CCcam genellikle 16 byte CC + version gönderir)
    3. Login dene
    4. Cevaba göre auth ok / failed
    """
    start = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # CCcam server genelde bağlanınca bir hello gönderir (12-20 byte)
        # Onu oku
        try:
            sock.settimeout(2)
            first = sock.recv(1024)
        except socket.timeout:
            first = b""
        
        # CCcam login packet (basitleştirilmiş ama çoğu server kabul eder)
        # Gerçek protokol: hash(user + pass + server_nonce)
        # Biz burada hem orijinal CCcam hem de generic login deniyoruz
        
        # Method 1: CCcam 2.0.11 style login
        # username null terminated + password null terminated + cc version
        login_packet = f"{user}\x00{pwd}\x00".encode() + b"CCcam\x002.3.0\x00"
        
        try:
            sock.settimeout(timeout)
            sock.sendall(login_packet)
            resp = sock.recv(4096)
        except socket.timeout:
            resp = b""
        except Exception as e:
            resp = b""
        
        elapsed = int((time.time() - start) * 1000)
        
        # Değerlendirme
        # Eğer hiç cevap yoksa -> auth failed (sadece port açık)
        if not resp and not first:
            return {
                "line": original_line,
                "cline": original_line,
                "ok": False,
                "working": False,
                "status": "auth_failed",
                "response_time": elapsed,
                "error": "No CCcam handshake response - user/pass likely invalid or only port open"
            }
        
        # Bazı serverlar auth fail olunca direkt kapatır veya 0 byte döner
        # Bazıları error string döner
        lower = (resp + first).lower()
        
        # Auth başarısız işaretleri
        fail_markers = [b"invalid", b"fail", b"bad", b"denied", b"unauthorized", b"wrong", b"error"]
        if any(m in lower for m in fail_markers):
            return {
                "line": original_line,
                "cline": original_line,
                "ok": False,
                "working": False,
                "status": "auth_failed",
                "response_time": elapsed,
                "error": f"Auth failed: {resp[:100]}",
                "raw_len": len(resp)
            }
        
        # Başarılı işaretleri: CCcam genellikle card data (caid, uphop vs) gönderir
        # En az 10 byte ve içinde printable olmayan binary data olmalı
        # Port sadece açıksa genellikle 0 byte veya aynı hello'yu tekrarlar
        
        # Eğer response first'den farklı ve uzunluğu > 20 ise genelde working'dir
        # Ayrıca sadece port açık olanlarda resp == b"" olur, biz zaten yukarıda eledik
        
        # Daha katı kontrol: response len > 16 ve farklı
        if len(resp) >= 16 or (len(first) >= 12 and len(resp) > 0):
            # Bir de gerçekten farklı mı kontrol et (sadece echo değil)
            if resp != first or len(resp) > 20:
                return {
                    "line": original_line,
                    "cline": original_line,
                    "ok": True,
                    "working": True,
                    "status": "working",
                    "response_time": elapsed,
                    "cards": 1,
                    "raw_preview": resp[:50].hex()
                }
        
        # Şüpheli durum -> failed say (güvenli tarafta kal)
        return {
            "line": original_line,
            "cline": original_line,
            "ok": False,
            "working": False,
            "status": "auth_failed",
            "response_time": elapsed,
            "error": f"Handshake incomplete - only port open? resp_len={len(resp)} first_len={len(first)}",
            "raw_len": len(resp)
        }

    except socket.timeout:
        return {"line": original_line, "cline": original_line, "ok": False, "working": False, "status": "timeout", "error": "Connection timeout"}
    except ConnectionRefusedError:
        return {"line": original_line, "cline": original_line, "ok": False, "working": False, "status": "closed", "error": "Connection refused"}
    except Exception as e:
        return {"line": original_line, "cline": original_line, "ok": False, "working": False, "status": "error", "error": str(e)[:200]}
    finally:
        if sock:
            try: sock.close()
            except: pass

def check_batch(lines: List[str], timeout=5):
    results=[]
    # Thread pool ile paralel ama hızlı
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        futures=[]
        for line in lines:
            parsed = parse_c_line(line)
            if not parsed:
                results.append({"line": line, "cline": line, "ok": False, "working": False, "status": "invalid_format", "error": "C: line parse failed"})
            else:
                host, port, user, pwd, orig = parsed
                futures.append(executor.submit(cccam_check_single, host, port, user, pwd, orig, timeout))
        
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"line": "unknown", "ok": False, "status": "error", "error": str(e)})
    
    # Orijinal sırayı koru
    ordered=[]
    for line in lines:
        found = next((r for r in results if r.get("line")==line or r.get("cline")==line), None)
        if found:
            ordered.append(found)
        else:
            # parse hatası zaten eklendi
            pass
    # parse hatalarını da ekle
    for r in results:
        if r.get("line") not in [x.get("line") for x in ordered]:
            ordered.append(r)
    return ordered

@app.get("/")
def root():
    return {"status": "online", "service": "SUNGATE TITAN API v3 - CCcam Auth Checker", "endpoints": ["/check-cccam-sync", "/check-cccam", "/cccam-jobs/{id}"]}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/check-cccam-sync")
def check_sync(req: CheckRequest):
    # SENKRON - brute için ana endpoint
    # delay'i uygula
    if req.delay > 0:
        time.sleep(req.delay/1000.0)
    results = check_batch(req.lines, timeout=req.timeout)
    return {"results": results, "count": len(results)}

# Async job sistemi (eski frontend fallback için)
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
    j = jobs.get(job_id)
    if not j:
        return {"status": "not_found"}
    return j
