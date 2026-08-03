import socket, time, uuid, re, hashlib
from typing import List
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import concurrent.futures

app = FastAPI(title="SUNGATE TITAN API v9 CCcam-PROTOCOL")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
jobs = {}

class CheckRequest(BaseModel):
    lines: List[str]
    timeout: int = 5
    delay: int = 0

# ===================== CCcam CryptographicBlock =====================
class CryptographicBlock:
    def __init__(self):
        self._keytable = [0] * 256
        self._state = 0
        self._counter = 0
        self._sum = 0

    def Init(self, key, length):
        for i in range(0, 256):
            self._keytable[i] = i
        j = 0
        for i in range(0, 256):
            j = 0xff & (j + key[i % length] + self._keytable[i])
            self._keytable[i], self._keytable[j] = self._keytable[j], self._keytable[i]
        self._state = key[0]
        self._counter = 0
        self._sum = 0

    def Decrypt(self, data, length):
        for i in range(0, length):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] =                 self._keytable[self._sum & 0xFF], self._keytable[self._counter]
            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter] + self._keytable[self._sum & 0xFF]) & 0xFF] ^ self._state
            z = data[i]
            self._state = 0xff & (self._state ^ z)

    def Encrypt(self, data, length):
        for i in range(0, length):
            self._counter = 0xff & (self._counter + 1)
            self._sum = self._sum + self._keytable[self._counter]
            self._keytable[self._counter], self._keytable[self._sum & 0xFF] =                 self._keytable[self._sum & 0xFF], self._keytable[self._counter]
            z = data[i]
            data[i] = z ^ self._keytable[(self._keytable[self._counter & 0xFF] + self._keytable[self._sum & 0xFF]) & 0xff] ^ self._state
            self._state = 0xff & (self._state ^ z)


def Xor(buf):
    cccam = "CCcam"
    for i in range(0, 8):
        buf[8 + i] = 0xff & (i * buf[i])
        if i < 5:
            buf[i] ^= ord(cccam[i])
    return buf


def FillArray(arr, source):
    if len(source) <= len(arr):
        for i in range(0, len(source)):
            arr[i] = source[i]
    else:
        for i in range(0, len(arr)):
            arr[i] = source[i]
    return arr


def GetPaddedString(string, padding):
    str_bytes = bytearray(string.encode())
    return FillArray(bytearray(padding), str_bytes)


def DoHandshake(sock):
    """CCcam handshake: recv 16b -> xor -> sha1 -> init blocks -> send encrypted sha1"""
    recvblock = CryptographicBlock()
    sendblock = CryptographicBlock()

    # 1. Receive 16 bytes (use recv instead of recv_into for reliability)
    data = sock.recv(16)
    if len(data) < 16:
        raise Exception(f"Incomplete seed: got {len(data)} bytes, expected 16")
    random = bytearray(data)

    # 2. XOR with "CCcam"
    random = Xor(random)

    # 3. SHA1 of XOR'd bytes
    sha1 = hashlib.sha1()
    sha1.update(random)
    sha1digest = bytearray(sha1.digest())
    sha1hash = FillArray(bytearray(20), sha1digest)

    # 4. Init recvblock with sha1hash, decrypt random
    recvblock.Init(sha1hash, 20)
    recvblock.Decrypt(random, 16)

    # 5. Init sendblock with decrypted random
    sendblock.Init(random, 16)

    # 6. Encrypt and send sha1hash (NO extra Decrypt step!)
    buffer = FillArray(bytearray(20), sha1hash)
    sendblock.Encrypt(buffer, 20)
    sock.send(buffer)

    return sendblock, recvblock


def SendMessage(data, length, sock, sendblock):
    buffer = FillArray(bytearray(length), data)
    sendblock.Encrypt(buffer, length)
    return sock.send(buffer)


# ===================== Parser =====================
def parse_c_line(line: str):
    line = line.strip()
    if not line:
        return None
    clean = re.sub(r'^C:\s*', '', line, flags=re.I).strip()
    parts = clean.split()
    if len(parts) < 4:
        return None
    try:
        host = parts[0]
        port = int(parts[1])
        user = parts[2]
        pwd = parts[3]
        if not (1 <= port <= 65535):
            return None
        return (host, port, user, pwd, line)
    except:
        return None


# ===================== CCcam Check =====================
def check_cccam_line(host, port, user, pwd, orig, timeout=5):
    sock = None
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        sendblock, recvblock = DoHandshake(sock)

        # Send username (20 bytes padded)
        user_array = GetPaddedString(user, 20)
        SendMessage(user_array, 20, sock, sendblock)

        # Send password (encrypted)
        pwd_array = GetPaddedString(pwd, len(pwd))
        sendblock.Encrypt(pwd_array, len(pwd_array))
        SendMessage(pwd_array, len(pwd_array), sock, sendblock)

        # Send "CCcam" (6 bytes padded)
        cccam_array = GetPaddedString("CCcam", 6)
        SendMessage(cccam_array, 6, sock, sendblock)

        # Receive response (20 bytes)
        received = bytearray(20)
        sock.settimeout(3.0)
        recv_count = sock.recv_into(received, 20)
        elapsed = int((time.time() - start) * 1000)

        if recv_count > 0:
            recvblock.Decrypt(received, 20)
            response = received.decode("ascii", errors="replace").rstrip('\x00').strip()
            if response == "CCcam":
                return {
                    "line": orig, "cline": orig, "ok": True, "working": True,
                    "status": "working", "response_time": elapsed,
                    "info": f"CCcam auth OK ({elapsed}ms)", "auth_method": "cccam_protocol",
                    "first_len": 16, "resp_len": recv_count
                }
            else:
                return {
                    "line": orig, "cline": orig, "ok": False, "working": False,
                    "status": "auth_failed", "response_time": elapsed,
                    "info": f"Bad ACK: {repr(response)}", "auth_method": "cccam_protocol",
                    "first_len": 16, "resp_len": recv_count
                }
        else:
            return {
                "line": orig, "cline": orig, "ok": False, "working": False,
                "status": "auth_failed", "response_time": elapsed,
                "info": "No response after auth", "auth_method": "cccam_protocol",
                "first_len": 16, "resp_len": 0
            }

    except socket.timeout:
        elapsed = int((time.time() - start) * 1000)
        return {
            "line": orig, "cline": orig, "ok": False, "working": False,
            "status": "timeout", "response_time": elapsed,
            "info": f"Socket timeout ({elapsed}ms)", "auth_method": "cccam_protocol",
            "first_len": 16, "resp_len": 0
        }
    except ConnectionRefusedError:
        elapsed = int((time.time() - start) * 1000)
        return {
            "line": orig, "cline": orig, "ok": False, "working": False,
            "status": "closed", "response_time": elapsed,
            "info": "Connection refused", "auth_method": "cccam_protocol",
            "first_len": 0, "resp_len": 0
        }
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return {
            "line": orig, "cline": orig, "ok": False, "working": False,
            "status": "error", "response_time": elapsed,
            "info": str(e)[:120], "auth_method": "cccam_protocol",
            "first_len": 16, "resp_len": 0
        }
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def check_batch(lines, timeout=5):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {}
        for line in lines:
            parsed = parse_c_line(line)
            if not parsed:
                results.append({
                    "line": line, "cline": line, "ok": False, "working": False,
                    "status": "invalid_format", "error": "parse failed", "auth_method": "cccam_protocol",
                    "first_len": 0, "resp_len": 0
                })
            else:
                host, port, user, pwd, orig = parsed
                fut = executor.submit(check_cccam_line, host, port, user, pwd, orig, timeout)
                futures[fut] = orig

        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({
                    "line": futures[fut], "ok": False, "status": "error",
                    "error": str(e), "auth_method": "cccam_protocol",
                    "first_len": 0, "resp_len": 0
                })

    ordered = []
    for line in lines:
        f = next((r for r in results if r.get("line") == line), None)
        if f:
            ordered.append(f)
    for r in results:
        if r.get("line") not in [o.get("line") for o in ordered]:
            ordered.append(r)
    return ordered


# ===================== Debug Single =====================
def check_cccam_debug(host, port, user, pwd, orig, timeout=5):
    sock = None
    start = time.time()
    details = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Step 1: Receive 16 bytes
        data = sock.recv(16)
        if len(data) < 16:
            raise Exception(f"Incomplete seed: {len(data)} bytes")
        random = bytearray(data)
        details.append({"method": 0, "is_open": False, "seed_len": len(random), "seed_hex": random.hex(), "resp_len": 0, "info": f"recv seed {len(random)}b"})

        # Step 2: Xor
        random = Xor(random)
        details.append({"method": 0, "is_open": False, "seed_len": len(random), "seed_hex": random.hex(), "resp_len": 0, "info": "XOR with CCcam"})

        # Step 3: SHA1
        sha1 = hashlib.sha1()
        sha1.update(random)
        sha1digest = bytearray(sha1.digest())
        sha1hash = FillArray(bytearray(20), sha1digest)
        details.append({"method": 0, "is_open": False, "seed_len": 0, "resp_len": 0, "info": f"SHA1: {sha1hash.hex()}"})

        # Step 4: Init blocks
        recvblock = CryptographicBlock()
        sendblock = CryptographicBlock()
        recvblock.Init(sha1hash, 20)
        recvblock.Decrypt(random, 16)
        sendblock.Init(random, 16)
        details.append({"method": 0, "is_open": False, "seed_len": 0, "resp_len": 0, "info": "Blocks initialized"})

        # Step 5: Send SHA1 hash (encrypted)
        buffer = FillArray(bytearray(20), sha1hash)
        sendblock.Encrypt(buffer, 20)
        sock.send(buffer)
        details.append({"method": 1, "is_open": False, "seed_len": 0, "resp_len": 0, "info": f"Sent SHA1 hash {buffer.hex()[:40]}..."})

        # Step 6: Send user
        user_array = GetPaddedString(user, 20)
        SendMessage(user_array, 20, sock, sendblock)
        details.append({"method": 1, "is_open": False, "seed_len": 0, "resp_len": 0, "info": f"Sent user: {user}"})

        # Step 7: Send password (encrypted)
        pwd_array = GetPaddedString(pwd, len(pwd))
        sendblock.Encrypt(pwd_array, len(pwd_array))
        SendMessage(pwd_array, len(pwd_array), sock, sendblock)
        details.append({"method": 2, "is_open": False, "seed_len": 0, "resp_len": 0, "info": "Sent encrypted password"})

        # Step 8: Send CCcam
        cccam_array = GetPaddedString("CCcam", 6)
        SendMessage(cccam_array, 6, sock, sendblock)
        details.append({"method": 2, "is_open": False, "seed_len": 0, "resp_len": 0, "info": "Sent CCcam ACK request"})

        # Step 9: Receive response
        received = bytearray(20)
        sock.settimeout(3.0)
        recv_count = sock.recv_into(received, 20)
        elapsed = int((time.time() - start) * 1000)

        if recv_count > 0:
            recvblock.Decrypt(received, 20)
            response = received.decode("ascii", errors="replace").rstrip('\x00').strip()
            details.append({"method": 3, "is_open": response == "CCcam", "seed_len": 0, "resp_len": recv_count, "resp_data": response, "info": f"Response: {repr(response)}"})
            is_open = (response == "CCcam")
            return {
                "line": orig,
                "is_open_after_login": is_open,
                "seed_len": 16,
                "resp_len": recv_count,
                "resp_data": response,
                "elapsed_ms": elapsed,
                "interpretation": "WORKING" if is_open else "AUTH_FAILED - bad ACK",
                "details": details,
                "any_working": is_open,
                "version": "v9-cccam",
                "info": f"CCcam auth {'OK' if is_open else 'FAILED'}: {repr(response)}"
            }
        else:
            details.append({"method": 3, "is_open": False, "seed_len": 0, "resp_len": 0, "info": "No response"})
            return {
                "line": orig,
                "is_open_after_login": False,
                "seed_len": 16,
                "resp_len": 0,
                "resp_data": "",
                "elapsed_ms": int((time.time() - start) * 1000),
                "interpretation": "AUTH_FAILED - no response",
                "details": details,
                "any_working": False,
                "version": "v9-cccam",
                "info": "No response after auth"
            }

    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        details.append({"method": 3, "is_open": False, "seed_len": 0, "resp_len": 0, "info": f"Error: {str(e)[:80]}"})
        return {
            "line": orig,
            "is_open_after_login": False,
            "seed_len": 16,
            "resp_len": 0,
            "resp_data": "",
            "elapsed_ms": elapsed,
            "interpretation": f"ERROR: {str(e)[:80]}",
            "details": details,
            "any_working": False,
            "version": "v9-cccam",
            "info": str(e)[:120]
        }
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


# ===================== Endpoints =====================
@app.get("/")
def root():
    return {
        "status": "online",
        "version": "v9-CCcam-PROTOCOL",
        "service": "SUNGATE TITAN API v9 - Real CCcam Auth",
        "endpoints": ["/check-cccam-sync", "/debug-single", "/health"]
    }

@app.get("/health")
def health():
    return {"ok": True, "version": "v9"}

@app.post("/check-cccam-sync")
def check_sync(req: CheckRequest):
    return {"results": check_batch(req.lines, timeout=req.timeout), "count": len(req.lines)}

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
    return check_cccam_debug(host, port, user, pwd, orig, req.timeout)
