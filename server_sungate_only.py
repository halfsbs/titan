import re, socket, time, uuid
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

app = FastAPI(title="Sungate CCcam Gercek Check API", version="4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cccam_jobs = {}

class ClineCheckRequest(BaseModel):
    lines: List[str]
    timeout: Optional[int] = 5
    delay: Optional[int] = 1

def parse_cline(line: str):
    line = line.strip()
    pattern = r'^C:\s*(\S+)\s+(\d+)\s+(\S+)\s+(\S+)'
    m = re.match(pattern, line, re.IGNORECASE)
    if not m:
        return None
    host, port, user, pwd = m.groups()
    return {"host": host, "port": int(port), "user": user, "pass": pwd, "original": line}

def check_single_cline(cline_str: str, timeout: int = 5):
    start = time.time()
    parsed = parse_cline(cline_str)
    if not parsed:
        return {"line": cline_str, "host": "-", "port": 0, "status": "error", "response_time": 0, "error": "Geçersiz format"}
    host = parsed["host"]
    port = parsed["port"]
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(2)
        try:
            data = sock.recv(1024)
        except:
            data = b""
        sock.close()
        elapsed = time.time() - start
        return {"line": cline_str, "host": host, "port": port, "status": "working", "response_time": int(elapsed*1000), "error": None}
    except socket.timeout:
        return {"line": cline_str, "host": host, "port": port, "status": "not_working", "response_time": int((time.time()-start)*1000), "error": "Timeout"}
    except ConnectionRefusedError:
        return {"line": cline_str, "host": host, "port": port, "status": "not_working", "response_time": int((time.time()-start)*1000), "error": "Reddedildi"}
    except socket.gaierror:
        return {"line": cline_str, "host": host, "port": port, "status": "error", "response_time": 0, "error": "DNS"}
    except Exception as e:
        return {"line": cline_str, "host": host, "port": port, "status": "not_working", "response_time": int((time.time()-start)*1000), "error": str(e)[:80]}

def run_cccam_job(job_id: str, lines: List[str], timeout: int, delay: int):
    try:
        cccam_jobs[job_id]["status"] = "running"
        cccam_jobs[job_id]["started_at"] = datetime.now().isoformat()
        cccam_jobs[job_id]["total"] = len(lines)
        cccam_jobs[job_id]["working"] = []
        cccam_jobs[job_id]["not_working"] = []
        cccam_jobs[job_id]["checked"] = 0
        for idx, line in enumerate(lines):
            if cccam_jobs[job_id].get("cancelled"):
                break
            result = check_single_cline(line.strip(), timeout=timeout)
            cccam_jobs[job_id]["checked"] += 1
            cccam_jobs[job_id]["last_result"] = result
            if result["status"] == "working":
                cccam_jobs[job_id]["working"].append(result)
            else:
                cccam_jobs[job_id]["not_working"].append(result)
            if delay > 0 and idx < len(lines)-1:
                time.sleep(delay)
        cccam_jobs[job_id]["status"] = "completed"
        cccam_jobs[job_id]["finished_at"] = datetime.now().isoformat()
    except Exception as e:
        import traceback
        cccam_jobs[job_id]["status"] = "failed"
        cccam_jobs[job_id]["error"] = str(e)
        cccam_jobs[job_id]["trace"] = traceback.format_exc()

@app.get("/")
def root():
    return {"status": "ok", "message": "Sungate Gercek TCP Check API", "endpoints": ["/check-cccam", "/check-cccam-sync", "/cccam-jobs/{id}"]}

@app.post("/check-cccam")
def check_cccam(req: ClineCheckRequest, background_tasks: BackgroundTasks):
    clean_lines = [l.strip() for l in req.lines if l.strip().upper().startswith("C:")]
    if not clean_lines:
        return {"error": "Gecerli C: yok"}
    job_id = str(uuid.uuid4())[:8]
    cccam_jobs[job_id] = {"job_id": job_id, "status": "queued", "lines": clean_lines, "total": len(clean_lines), "checked": 0, "working": [], "not_working": [], "created_at": datetime.now().isoformat()}
    background_tasks.add_task(run_cccam_job, job_id, clean_lines, req.timeout, req.delay)
    return {"job_id": job_id, "status": "queued", "total": len(clean_lines)}

@app.get("/cccam-jobs/{job_id}")
def get_cccam_job(job_id: str):
    return cccam_jobs.get(job_id, {"error": "not found"})

@app.post("/cccam-jobs/{job_id}/stop")
def stop_cccam_job(job_id: str):
    if job_id in cccam_jobs:
        cccam_jobs[job_id]["cancelled"] = True
        cccam_jobs[job_id]["status"] = "stopped"
        return {"status": "stopped"}
    return {"error": "not found"}

@app.post("/check-cccam-sync")
def check_cccam_sync(req: ClineCheckRequest):
    clean_lines = [l.strip() for l in req.lines if l.strip().upper().startswith("C:")]
    results = []
    for line in clean_lines[:50]:
        results.append(check_single_cline(line, timeout=req.timeout))
        if req.delay > 0:
            time.sleep(req.delay)
    working = [r for r in results if r["status"] == "working"]
    not_working = [r for r in results if r["status"] != "working"]
    return {"total": len(results), "working": working, "not_working": not_working, "results": results}

# Northflank / Render / Railway için
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
