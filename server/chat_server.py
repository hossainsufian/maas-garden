#!/usr/bin/env python3
"""Tiny chat server for Maa's Garden. Python 3 standard library only.

Run:      python3 chat_server.py            (listens on 127.0.0.1:8790)
Public:   tailscale funnel --bg 8790        (gives a public https:// address)

API (same shape the website already uses):
  GET  /messages.json   -> {"<key>": {"name","text","t","uid","img?"}, ...}  (latest 100)
  POST /messages.json   -> body {"name","text","t","uid","img?"}  -> {"name":"<key>"}
Messages are saved in messages.db.json next to this file.
"""
import json, os, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("CHAT_HOST", "127.0.0.1")
PORT = int(os.environ.get("CHAT_PORT", "8790"))
ALLOWED = {"https://hossainsufian.github.io", "http://localhost:8765", "http://127.0.0.1:8765"}
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "messages.db.json")
KEEP = 500            # messages kept on disk
MAX_BODY = 200_000    # bytes per request
MAX_IMG = 120_000     # characters in a photo data URL

lock = threading.Lock()
last_post = {}        # ip -> time of last post (simple rate limit)
messages = []         # list of [key, message]
counter = 0

def load():
    global messages, counter
    try:
        with open(DB, encoding="utf-8") as f:
            messages = json.load(f)
        counter = max((int(k.split("-")[1]) for k, _ in messages), default=0)
    except Exception:
        messages = []

def save():
    tmp = DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(messages[-KEEP:], f, ensure_ascii=False)
    os.replace(tmp, DB)

def clean(m):
    """Validate one incoming message; return a safe dict or None."""
    if not isinstance(m, dict):
        return None
    name, text, uid = m.get("name"), m.get("text", ""), m.get("uid")
    img = m.get("img")
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

class H(BaseHTTPRequestHandler):
    server_version = "GardenChat"

    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_GET(self):
        if self.path.split("?")[0] != "/messages.json":
            return self._send(404, {"error": "not found"})
        with lock:
            latest = messages[-100:]
        self._send(200, {k: m for k, m in latest})

    def do_POST(self):
        global counter
        if self.path.split("?")[0] != "/messages.json":
            return self._send(404, {"error": "not found"})
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        now = time.time()
        if now - last_post.get(ip, 0) < 0.8:
            return self._send(429, {"error": "slow down"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"error": "too large"})
            m = clean(json.loads(self.rfile.read(n)))
        except Exception:
            m = None
        if not m:
            return self._send(400, {"error": "bad message"})
        last_post[ip] = now
        with lock:
            counter += 1
            key = "m-%012d" % counter       # sorts in posting order
            messages.append([key, m])
            save()
        self._send(200, {"name": key})

    def log_message(self, *a):  # keep the console quiet
        pass

if __name__ == "__main__":
    load()
    print(f"Garden chat server on http://{HOST}:{PORT}  ({len(messages)} saved messages)")
    try:
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
