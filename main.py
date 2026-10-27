import os, re, hashlib, tempfile
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

load_dotenv()
VT = "https://www.virustotal.com/api/v3"
SHA = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_VT = 650 * 1024 * 1024
MAX_STATIC = 100 * 1024 * 1024
SMALL = 32 * 1024 * 1024
app = FastAPI(title="klaws antivirus web")

SENSITIVE = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES", "READ_PHONE_STATE",
    "BIND_DEVICE_ADMIN", "WRITE_SETTINGS",
}
COMBOS = [
    ("READ_SMS", "INTERNET"),
    ("RECEIVE_SMS", "INTERNET"),
    ("READ_CONTACTS", "INTERNET"),
    ("RECORD_AUDIO", "INTERNET"),
    ("SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"),
]


async def vt(method, path, **kw):
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        raise HTTPException(503, "no_key")
    url = path if path.startswith("http") else VT + path
    try:
        async with httpx.AsyncClient(timeout=300) as c:
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


@app.get("/")
async def home():
    return FileResponse("index.html")


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
    if r.status_code >= 400:
        raise HTTPException(502, "network")
    return summarize(sha, r.json())


async def save(f, limit: int):
    if not (getattr(f, "filename", "") or "").lower().endswith(".apk"):
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
        if first:
            raise HTTPException(415, "unsupported_type")
    except BaseException:
        t.close()
        os.remove(t.name)
        raise
    t.close()
    return t.name, h.hexdigest()


async def get_upload(request: Request):
    try:
        form = await request.form()
    except Exception:
        raise HTTPException(500, "generic")
    return form


def analyze(path):
    try:
        try:
            from androguard.core.apk import APK
        except ImportError:
            from androguard.core.bytecodes.apk import APK
    except ImportError:
        return {"available": False, "reason": "androguard_missing"}
    try:
        apk = APK(path)
        if not apk.is_valid_APK():
            return {"available": False, "reason": "not_valid_apk"}
        package = apk.get_package()
        perms = sorted(set(apk.get_permissions()))
    except Exception:
        return {"available": False, "reason": "not_valid_apk"}
    short = {p.split(".")[-1] for p in perms}
    sensitive = sorted(p for p in perms if p.split(".")[-1] in SENSITIVE)
    combos = [f"{a} + {b}" for a, b in COMBOS if a in short and b in short]
    sigs = []
    try:
        for c in apk.get_certificates():
            v = c["tbs_certificate"]["validity"]
            sigs.append({
                "subject": c.subject.human_friendly,
                "not_before": v["not_before"].native.isoformat(),
                "not_after": v["not_after"].native.isoformat(),
            })
    except Exception:
        pass
    return {"available": True, "package": package, "permissions": perms,
            "sensitive": sensitive, "combos": combos, "signature": sigs}


@app.post("/api/static")
async def static_scan(request: Request):
    form = await get_upload(request)
    f = form.get("file")
    if f is None or not hasattr(f, "read"):
        raise HTTPException(400, "generic")
    path, _ = await save(f, MAX_STATIC)
    try:
        return await run_in_threadpool(analyze, path)
    finally:
        os.remove(path)


@app.post("/api/submit")
async def submit(request: Request):
    form = await get_upload(request)
    if form.get("consent") != "true":
        raise HTTPException(400, "consent_required")
    f = form.get("file")
    if f is None or not hasattr(f, "read"):
        raise HTTPException(400, "generic")
    path, sha = await save(f, MAX_VT)
    try:
        url = "/files"
        if os.path.getsize(path) > SMALL:
            r = await vt("GET", "/files/upload_url")
            if r.status_code >= 400:
                raise HTTPException(502, "network")
            url = r.json()["data"]
        with open(path, "rb") as fh:
            r = await vt("POST", url, files={"file": (f.filename, fh)})
        if r.status_code >= 400:
            raise HTTPException(502, "network")
        return {"analysis_id": r.json()["data"]["id"], "sha256": sha}
    finally:
        os.remove(path)


@app.get("/api/analysis/{aid}")
async def analysis(aid: str):
    if not aid or len(aid) > 200:
        raise HTTPException(400, "generic")
    r = await vt("GET", f"/analyses/{aid}")
    if r.status_code >= 400:
        raise HTTPException(502, "network")
    return {"status": r.json()["data"]["attributes"]["status"]}
