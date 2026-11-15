#!/usr/bin/env python3
"""Server for Maa's Garden: family chat + the plant list. Python 3 standard library only.

Run:      python3 chat_server.py            (listens on 127.0.0.1:8790)
Public:   tailscale funnel --bg 8790        (gives a public https:// address)

Secrets live OUTSIDE the repo, in ~/garden-chat-data/ :
  family_code   password for reading/writing the chat
  admin_code    password for adding/editing/deleting plants (Maa only)

API
  GET    /messages.json        chat messages            (needs X-Family-Code)
  POST   /messages.json        send a chat message      (needs X-Family-Code)
  GET    /plants.json          the plant list           (public)
  POST   /plants.json          add a plant              (needs X-Admin-Code)
  PUT    /plants/<id>.json     edit a plant             (needs X-Admin-Code)
  DELETE /plants/<id>.json     delete a plant           (needs X-Admin-Code)
  GET    /admin/check          is the admin code right? (needs X-Admin-Code)
"""
import hmac, json, os, re, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("CHAT_HOST", "127.0.0.1")
PORT = int(os.environ.get("CHAT_PORT", "8790"))
ALLOWED = {"https://hossainsufian.github.io", "http://localhost:8765", "http://127.0.0.1:8765"}
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "messages.db.json")
PDB = os.path.join(HERE, "plants.db.json")
DATA = os.path.expanduser("~/garden-chat-data")
FAMILY_FILE = os.environ.get("CHAT_CODE_FILE", os.path.join(DATA, "family_code"))
ADMIN_FILE = os.environ.get("CHAT_ADMIN_FILE", os.path.join(DATA, "admin_code"))

KEEP = 500             # chat messages kept on disk
MAX_BODY = 200_000     # bytes per chat request
MAX_PLANT_BODY = 700_000
MAX_IMG = 120_000      # chat photo (data URL characters)
MAX_PLANT_IMG = 450_000
MAX_PLANTS = 200
TYPES = {"", "Flower", "Vegetable", "Herb", "Tree", "Indoor", "Succulent", "Other"}

lock = threading.Lock()
last_post = {}         # ip -> time of last chat post
fails = {}             # (ip, kind) -> recent wrong-password times
messages, counter = [], 0
plants, pcounter = [], 0


def read_secret(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""      # missing file -> nobody gets in (fails closed)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def clean_msg(m):
    if not isinstance(m, dict):
        return None
    name, text, uid, img = m.get("name"), m.get("text", ""), m.get("uid"), m.get("img")
    if not isinstance(name, str) or not isinstance(text, str) or not isinstance(uid, str):
        return None
    name, text = name.strip()[:24], text.strip()[:300]
    if not name or (not text and not img):
        return None
    out = {"name": name, "text": text, "t": int(time.time() * 1000), "uid": uid[:40]}
    if img is not None:
        if not (isinstance(img, str) and img.startswith("data:image/") and len(img) <= MAX_IMG):
            return None
        out["img"] = img
    return out


def s(d, k, n):
    v = d.get(k, "")
    return v.strip()[:n] if isinstance(v, str) else ""


def clean_plant(d):
    if not isinstance(d, dict):
        return None
    name = s(d, "name", 60)
    if not name:
        return None
    typ = s(d, "type", 20)
    if typ not in TYPES:
        typ = "Other"
    every = d.get("every", "")
    try:
        every = int(every) if every not in ("", None) else ""
        if every != "" and not (1 <= every <= 365):
            every = ""
    except Exception:
        every = ""
    last = s(d, "last", 10)
    if last and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", last):
        last = ""
    photo = d.get("photo", "")
    if not isinstance(photo, str):
        photo = ""
    if photo and not (re.fullmatch(r"images/[\w.\-]+", photo) or
                      (photo.startswith("data:image/") and len(photo) <= MAX_PLANT_IMG)):
        return None
    return {"name": name, "where": s(d, "where", 40), "type": typ, "sun": s(d, "sun", 20),
            "every": every, "last": last, "notes": s(d, "notes", 600), "photo": photo}


class H(BaseHTTPRequestHandler):
    server_version = "GardenServer"

    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Family-Code, X-Admin-Code")

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()

    def _auth(self, kind):
        """kind = 'family' or 'admin'. True if the password is right; otherwise replies with an error."""
        ip, now = self._ip(), time.time()
        recent = [t for t in fails.get((ip, kind), []) if now - t < 60]
        if len(recent) >= 8:
            self._send(429, {"error": "too many wrong passwords, wait a minute"})
            return False
        secret = read_secret(FAMILY_FILE if kind == "family" else ADMIN_FILE)
        given = self.headers.get("X-Family-Code" if kind == "family" else "X-Admin-Code", "")
        if secret and hmac.compare_digest(given.encode(), secret.encode()):
            return True
        fails[(ip, kind)] = recent + [now]
        self._send(401, {"error": kind + " password needed"})
        return False

    def _body(self, limit):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > limit:
                self._send(413, {"error": "too large"})
                return None
            return json.loads(self.rfile.read(n))
        except Exception:
            self._send(400, {"error": "bad request"})
            return None

    def _path(self):
        return self.path.split("?")[0]

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        p = self._path()
        if p == "/plants.json":
            with lock:
                return self._send(200, list(plants))
        if p == "/admin/check":
            if self._auth("admin"):
                self._send(200, {"ok": True})
            return
        if p == "/messages.json":
            if not self._auth("family"):
                return
            with lock:
                latest = messages[-100:]
            return self._send(200, {k: m for k, m in latest})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        global counter, pcounter
        p = self._path()
        if p == "/plants.json":
            if not self._auth("admin"):
                return
            d = self._body(MAX_PLANT_BODY)
            if d is None:
                return
            c = clean_plant(d)
            if not c:
                return self._send(400, {"error": "bad plant"})
            with lock:
                if len(plants) >= MAX_PLANTS:
                    return self._send(400, {"error": "too many plants"})
                pcounter += 1
                c["id"] = "p%d" % pcounter
                plants.insert(0, c)
                save_json(PDB, plants)
            return self._send(200, c)
        if p == "/messages.json":
            if not self._auth("family"):
                return
            ip, now = self._ip(), time.time()
            if now - last_post.get(ip, 0) < 0.8:
                return self._send(429, {"error": "slow down"})
            d = self._body(MAX_BODY)
            if d is None:
                return
            m = clean_msg(d)
            if not m:
                return self._send(400, {"error": "bad message"})
            last_post[ip] = now
            with lock:
                counter += 1
                key = "m-%012d" % counter       # sorts in posting order
                messages.append([key, m])
                save_json(DB, messages[-KEEP:])
            return self._send(200, {"name": key})
        self._send(404, {"error": "not found"})

    def _plant_id(self):
        m = re.fullmatch(r"/plants/(p\d+)\.json", self._path())
        return m.group(1) if m else None

    def do_PUT(self):
        pid = self._plant_id()
        if not pid:
            return self._send(404, {"error": "not found"})
        if not self._auth("admin"):
            return
        d = self._body(MAX_PLANT_BODY)
        if d is None:
            return
        c = clean_plant(d)
        if not c:
            return self._send(400, {"error": "bad plant"})
        with lock:
            for i, old in enumerate(plants):
                if old["id"] == pid:
                    c["id"] = pid
                    plants[i] = c
                    save_json(PDB, plants)
                    return self._send(200, c)
        self._send(404, {"error": "no such plant"})

    def do_DELETE(self):
        pid = self._plant_id()
        if not pid:
            return self._send(404, {"error": "not found"})
        if not self._auth("admin"):
            return
        with lock:
            before = len(plants)
            plants[:] = [x for x in plants if x["id"] != pid]
            if len(plants) == before:
                return self._send(404, {"error": "no such plant"})
            save_json(PDB, plants)
        self._send(200, {"ok": True})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    messages = load_json(DB, [])
    counter = max((int(k.split("-")[1]) for k, _ in messages), default=0)
    plants = load_json(PDB, [])
    pcounter = max((int(x["id"][1:]) for x in plants), default=0)
    print(f"Garden server on http://{HOST}:{PORT}  ({len(messages)} messages, {len(plants)} plants)")
    try:
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
