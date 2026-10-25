import os, re, hashlib, tempfile
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles

load_dotenv()
VT = "https://www.virustotal.com/api/v3"
SHA = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_VT = 650 * 1024 * 1024
MAX_STATIC = 100 * 1024 * 1024
app = FastAPI(title="klaws antivirus web")


async def vt(method, path, **kw):
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        raise HTTPException(503, "no_key")
    url = path if path.startswith("http") else VT + path
    try:
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.request(method, url, headers={"x-apikey": key}, **kw)
    except httpx.TimeoutException:
        raise HTTPException(504, "timeout")
    except httpx.HTTPError:
        raise HTTPException(502, "network")
    if r.status_code == 429:
        raise HTTPException(429, "rate_limit")
    if r.status_code in (401, 403):
        raise HTTPException(503, "bad_key")
    return r


def summarize(sha, j):
    a = j["data"]["attributes"]
    s = a.get("last_analysis_stats", {})
    mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
    total = sum(s.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    if total == 0:
        verdict = "unknown"
    elif mal >= 3:
        verdict = "malicious"
    elif mal or sus:
        verdict = "suspicious"
    else:
        verdict = "no_detections"
    engines = [{"name": n, "category": e.get("category"), "result": e.get("result")}
               for n, e in a.get("last_analysis_results", {}).items()]
    return {"verdict": verdict, "sha256": sha, "name": a.get("meaningful_name"),
            "type": a.get("type_description"), "size": a.get("size"),
            "malicious": mal, "suspicious": sus, "total": total, "engines": engines}


@app.get("/api/config")
async def config():
    return {"vt_configured": bool(os.environ.get("VT_API_KEY"))}


@app.get("/api/hash/{sha}")
async def by_hash(sha: str):
    if not SHA.match(sha):
        raise HTTPException(400, "bad_hash")
    sha = sha.lower()
    r = await vt("GET", f"/files/{sha}")
    if r.status_code == 404:
        return {"verdict": "unknown", "sha256": sha, "total": 0, "malicious": 0,
                "suspicious": 0, "engines": []}
    r.raise_for_status()
    return summarize(sha, r.json())


async def save(f: UploadFile, limit: int):
    if not (f.filename or "").lower().endswith(".apk"):
        raise HTTPException(415, "unsupported_type")
    h, n, first = hashlib.sha256(), 0, True
    t = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
    try:
        while chunk := await f.read(1 << 20):
            if first and chunk[:2] != b"PK":
                raise HTTPException(415, "unsupported_type")
            first = False
            n += len(chunk)
            if n > limit:
                raise HTTPException(413, "too_large")
            h.update(chunk)
            t.write(chunk)
    except BaseException:
        t.close()
        os.remove(t.name)
        raise
    t.close()
    return t
