# เว็บ ตัวนี้ http://localhost:5000
import contextlib
import csv
import io
import json
import os
import re
import sqlite3
import time
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]  # ข้อความสุ่มยาวๆ ไว้เข้ารหัส session
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",  # กัน request ข้ามเว็บ (CSRF) ของ /api/data
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",  # ตั้งเป็น 1 เมื่อขึ้นเว็บจริง (https)
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # ข้อมูลหนึ่งครั้งไม่เกิน 5 MB
)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"  # เข้าถึงได้เฉพาะไฟล์ที่แอปนี้สร้างเอง
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3"
DATA_FILE_NAME = "money-walk-data.csv"

@app.route('/google6e902da1b45f8bcb.html')
def google_verify():
    return app.send_static_file('google6e902da1b45f8bcb.html')

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": f"openid email profile {DRIVE_SCOPE}"},
)


# ---------------------------------------------------------------------------
# เก็บ refresh token ฝั่งเซิร์ฟเวอร์ (ผูกกับรหัสผู้ใช้ Google) เพื่อให้ต่ออายุสิทธิ์เข้า Drive ได้เอง
# ไม่ต้องให้ผู้ใช้กดอนุญาตซ้ำทุกครั้งที่ล็อกอิน
# ตอนขึ้นเว็บจริง ควรเข้ารหัสค่านี้ หรือใช้ฐานข้อมูลของโฮสต์
# ---------------------------------------------------------------------------
TOKEN_DB = os.environ.get("TOKEN_DB", "tokens.db")


@contextlib.contextmanager
def token_db():
    conn = sqlite3.connect(TOKEN_DB)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS tokens (sub TEXT PRIMARY KEY, refresh_token TEXT NOT NULL)")
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_refresh_token(sub, refresh_token):
    with token_db() as c:
        c.execute(
            "INSERT INTO tokens(sub, refresh_token) VALUES(?, ?) "
            "ON CONFLICT(sub) DO UPDATE SET refresh_token = excluded.refresh_token",
            (sub, refresh_token),
        )


def get_refresh_token(sub):
    with token_db() as c:
        row = c.execute("SELECT refresh_token FROM tokens WHERE sub = ?", (sub,)).fetchone()
    return row[0] if row else None


def delete_refresh_token(sub):
    with token_db() as c:
        c.execute("DELETE FROM tokens WHERE sub = ?", (sub,))


# ---------------------------------------------------------------------------
# สิทธิ์เข้าใช้งาน
# ---------------------------------------------------------------------------
def is_logged_in():
    u = session.get("user")
    return bool(u and u.get("sub") and session.get("gtoken"))


def login_required(view):
    """หน้าไหนติดตัวนี้ ต้องล็อกอินก่อน ไม่งั้นเด้งไปหน้า login"""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            # session เก่าที่ล็อกอินก่อนมีระบบ Drive จะถูกให้ล็อกอินใหม่ เพื่อขอสิทธิ์เพิ่ม
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def api_login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return jsonify(error="reauth"), 401
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Google Drive
# ---------------------------------------------------------------------------
class Reauth(Exception):
    """ต้องให้ผู้ใช้ล็อกอินใหม่ (token หมดอายุถาวร / ไม่ได้อนุญาต Drive)"""


class DriveError(Exception):
    pass


def drive_error(action, resp):
    """แปลง error ของ Drive API เป็นข้อความที่อ่านรู้เรื่อง (ใช้ทั้งใน log และแสดงในหน้าเว็บ)"""
    reason, message = "", ""
    try:
        err = resp.json().get("error", {})
        message = err.get("message", "") if isinstance(err, dict) else str(err)
        errors = (err.get("errors") or []) if isinstance(err, dict) else []
        reason = errors[0].get("reason", "") if errors else (err.get("status", "") if isinstance(err, dict) else "")
    except ValueError:
        message = resp.text[:200]
    if reason == "accessNotConfigured" or "has not been used" in message or "is disabled" in message:
        return DriveError(
            "ยังไม่ได้เปิด Google Drive API ในโปรเจกต์ Google Cloud "
            "(เปิดที่ https://console.cloud.google.com/apis/library/drive.googleapis.com แล้วรอ 1-2 นาที)"
        )
    return DriveError(f"{action} {resp.status_code} {reason} {message}".strip())


def refresh_access_token():
    sub = session["user"]["sub"]
    refresh_token = get_refresh_token(sub)
    if not refresh_token:
        return None
    resp = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        try:
            if resp.json().get("error") == "invalid_grant":  # ผู้ใช้เพิกถอนสิทธิ์แล้ว
                delete_refresh_token(sub)
        except ValueError:
            pass
        return None
    body = resp.json()
    session["gtoken"] = {
        "access_token": body["access_token"],
        "expires_at": int(time.time()) + int(body.get("expires_in", 3600)),
    }
    session.modified = True
    return body["access_token"]


def get_access_token():
    g = session.get("gtoken") or {}
    if g.get("access_token") and g.get("expires_at", 0) - 60 > time.time():
        return g["access_token"]
    return refresh_access_token()


def drive(method, url, headers=None, **kwargs):
    """เรียก Drive API ถ้า token หมดอายุจะต่ออายุแล้วลองอีกครั้ง"""
    for attempt in range(2):
        token = get_access_token() if attempt == 0 else refresh_access_token()
        if not token:
            raise Reauth()
        resp = requests.request(
            method, url, headers={**(headers or {}), "Authorization": f"Bearer {token}"}, timeout=20, **kwargs
        )
        if resp.status_code == 401 and attempt == 0:
            continue
        if resp.status_code == 401:
            raise Reauth()
        if resp.status_code == 403 and "insufficient" in resp.text.lower():
            raise Reauth()
        return resp
    raise Reauth()


def find_file_id(name):
    resp = drive(
        "GET",
        f"{DRIVE_API}/files",
        params={
            "q": f"name = '{name}' and trashed = false",
            "spaces": "drive",
            "fields": "files(id,name,createdTime)",
            "orderBy": "createdTime",
            "pageSize": 10,
        },
    )
    if resp.status_code != 200:
        raise drive_error("list", resp)
    files = resp.json().get("files", [])
    return files[0]["id"] if files else None

# ---------------------------------------------------------------------------
# รูปแบบไฟล์ CSV ใหม่: แบ่งเป็นหมวด อ่านง่าย หัวตารางภาษาไทย
# แต่ละหมวดขึ้นต้นด้วยแถว "■ ชื่อหมวด" ตามด้วยแถวหัวตาราง แล้วเป็นข้อมูล คั่นหมวดด้วยแถวว่าง
# ตอนอ่านจะหาคอลัมน์จาก "ชื่อหัวตาราง" ไม่ใช่ลำดับ จึงสลับคอลัมน์ได้
# ---------------------------------------------------------------------------
TEXT_COLS = {"asset", "to", "topic", "note", "name"}
_GUARD = re.compile(r"^'[=+\-@\t\r]")


def _text(col, s):
    s = s or ""
    return s[1:] if col in TEXT_COLS and _GUARD.match(s) else s


def _u(s):
    s = s or ""
    return s[1:] if _GUARD.match(s) else s


def _num(s):
    try:
        f = float(str(s).replace(",", "").strip())
    except (TypeError, ValueError):
        return 0
    return int(f) if f.is_integer() else f


TH_TZ = timezone(timedelta(hours=7))
S_META, S_SET, S_ENTRY, S_FAV, S_ASSET, S_LIAB, S_TOPIC = (
    "ข้อมูลไฟล์", "ตั้งค่า", "รายการรายรับ-รายจ่าย-โอน", "รายการโปรด", "ทรัพย์สิน", "หนี้สิน", "หัวข้อ",
)
SECTIONS = {S_META, S_SET, S_ENTRY, S_FAV, S_ASSET, S_LIAB, S_TOPIC}
C_ID = "รหัส (ห้ามแก้)"
TYPE_TH = {"income": "รายรับ", "expense": "รายจ่าย", "transfer": "โอนเงิน"}
TYPE_EN = {v: k for k, v in TYPE_TH.items()}
TYPE_EN.update({k: k for k in TYPE_TH})

# (กลุ่ม, คีย์, ชื่อที่แสดง, ชนิดค่า, แปลงค่าเป็นคำไทย)
SETTING_SPEC = [
    (None, "budget", "เงินตั้งต้น (บาท)", "num", {}),
    ("settings", "period", "รอบรีเซ็ตหน้าหลัก", "text", {"day": "รายวัน", "month": "รายเดือน", "year": "รายปี"}),
    ("settings", "startDay", "รอบรายเดือน: เริ่มทุกวันที่", "num", {}),
    ("settings", "yMonth", "รอบรายปี: เริ่มเดือนที่", "num", {}),
    ("settings", "yDay", "รอบรายปี: เริ่มวันที่", "num", {}),
    ("settings", "carry", "เมื่อขึ้นรอบใหม่", "text", {True: "ยกยอดเงินที่เหลือ", False: "เริ่มใหม่ด้วยเงินตั้งต้น"}),
    ("settings", "theme", "ธีม", "text", {"light": "สว่าง", "dark": "มืด", "auto": "ตามเครื่อง"}),
    ("settings", "accent", "สีหลัก", "text", {}),
    ("settings", "lastBackup", "สำรองล่าสุด (รหัสเวลา)", "num", {}),
    ("stats", "m", "คาดการณ์: จำนวนเดือน", "num", {}),
    ("stats", "rate", "คาดการณ์: ดอกเบี้ยต่อปี (%)", "num", {}),
    ("stats", "goal", "คาดการณ์: เป้าหมายเงิน (บาท)", "num", {}),
    ("stats", "d", "กราฟรายวัน: ช่วงวัน", "numtext", {"cycle": "รอบนี้"}),
]
SPEC_BY_LABEL = {s[2]: s for s in SETTING_SPEC}
SPEC_KEYS = {(s[0], s[1]) for s in SETTING_SPEC}


def _t(v):
    """ข้อความ: กัน Excel ตีความเป็นสูตร"""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _n(v):
    return "" if v is None else v


def _decode(raw, kind, mp):
    raw = (raw or "").strip()
    for k, v in mp.items():
        if v == raw:
            return k
    if kind == "num":
        return _num(raw)
    if kind == "numtext":
        return _num(raw) if re.fullmatch(r"-?\d+(\.\d+)?", raw) else raw
    return raw


def data_to_csv(updated, data):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    first = [True]

    def section(name, headers, rows):
        if not first[0]:
            w.writerow([])
        first[0] = False
        w.writerow(["■ " + name, f"{len(rows)} รายการ"])
        w.writerow(headers)
        w.writerows(rows)

    when = datetime.fromtimestamp(updated / 1000, TH_TZ).strftime("%Y-%m-%d %H:%M:%S")
    section(S_META, ["หัวข้อ", "ค่า", "หมายเหตุ"], [
        ["แก้ไขล่าสุด", when, "แสดงเฉยๆ ไม่ได้ใช้อ่านกลับ"],
        ["รหัสเวลาแก้ไข", updated, "ห้ามแก้ ใช้ตรวจว่าเครื่องอื่นแก้ไปแล้วหรือยัง"],
        ["เวอร์ชันไฟล์", 3, ""],
        ["วิธีใช้", "ไฟล์นี้แอปสร้างให้ เปิดดูได้ แก้ได้ แต่ไม่ควรแก้คอลัมน์รหัส และวันที่ต้องเป็นแบบ 2026-11-05", ""],
    ])

    rows = []
    for grp, key, label, kind, mp in SETTING_SPEC:
        src = data.get("budget") if grp is None else (data.get(grp) or {}).get(key)
        if src is None:
            continue
        if isinstance(src, (str, int, float, bool)):
            rows.append([label, _t(mp[src]) if src in mp else _t(src)])
        else:
            rows.append([f"{grp}.{key}", json.dumps(src, ensure_ascii=False)])
    for grp in ("stats", "settings"):  # ค่าอื่นที่ไม่รู้จัก เก็บไว้ไม่ให้หาย
        for k, v in (data.get(grp) or {}).items():
            if (grp, k) not in SPEC_KEYS:
                rows.append([f"{grp}.{k}", json.dumps(v, ensure_ascii=False)])
    section(S_SET, ["รายการ", "ค่า"], rows)

    ents = [e for e in (data.get("entries") or []) if isinstance(e, dict)]
    ents.sort(key=lambda e: (str(e.get("date") or ""), _num(e.get("id"))))
    section(S_ENTRY, ["วันที่", "ประเภท", "หัวข้อ", "จำนวนเงิน", "ที่เก็บ", "โอนไปที่", "หมายเหตุ", C_ID], [
        [_t(e.get("date")), TYPE_TH.get(e.get("type"), ""), _t(e.get("topic")), _n(e.get("amount")),
         _t(e.get("asset")), _t(e.get("to")), _t(e.get("note")), _n(e.get("id"))] for e in ents])

    favs = [f for f in (data.get("favs") or []) if isinstance(f, dict)]
    section(S_FAV, ["ประเภท", "หัวข้อ", "จำนวนเงิน", "ที่เก็บ", "โอนไปที่", "หมายเหตุ", C_ID], [
        [TYPE_TH.get(f.get("type"), ""), _t(f.get("topic")), _n(f.get("amount")),
         _t(f.get("asset")), _t(f.get("to")), _t(f.get("note")), _n(f.get("id"))] for f in favs])

    assets = [a for a in (data.get("assets") or []) if isinstance(a, dict)]
    section(S_ASSET, ["ชื่อ", "ยอดตั้งต้น", "สี", C_ID], [
        [_t(a.get("name")), _n(a.get("base")), _t(a.get("color")), _t(a.get("id"))] for a in assets])

    liabs = [x for x in (data.get("liabs") or []) if isinstance(x, dict)]
    section(S_LIAB, ["ชื่อหนี้", "จำนวนเงิน", C_ID], [
        [_t(x.get("name")), _n(x.get("amount")), _t(x.get("id"))] for x in liabs])

    topics = [t for t in (data.get("topics") or []) if isinstance(t, dict)]
    section(S_TOPIC, ["ประเภท", "ชื่อหัวข้อ", "สี"], [
        [TYPE_TH.get(t.get("kind"), ""), _t(t.get("name")), _t(t.get("color"))] for t in topics])

    return ("\ufeff" + out.getvalue()).encode("utf-8")  # BOM ให้ Excel เปิดภาษาไทยไม่เพี้ยน


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def csv_to_remote_legacy(raw):
    """อ่านไฟล์ CSV รูปแบบเก่า (คอลัมน์ table/key/value)"""
    data, updated = {}, 0
    for r in csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))):
        t = r.get("table")

        def g(c):
            return _text(c, r.get(c))

        if t == "meta":
            if r.get("key") == "updated":
                updated = int(_num(r.get("value")))
        elif t == "kv":
            key = r.get("key") or ""
            try:
                val = json.loads(r.get("value") or "null")
            except ValueError:
                continue
            if key == "budget":
                data["budget"] = val
            elif "." in key:
                grp, k = key.split(".", 1)
                if grp in ("stats", "settings"):
                    data.setdefault(grp, {})[k] = val
        elif t == "entry":
            data.setdefault("entries", []).append({
                "id": _num(r.get("id")), "date": g("date"), "type": g("type"), "amount": _num(r.get("amount")),
                "asset": g("asset"), "to": g("to"), "topic": g("topic"), "note": g("note"),
            })
        elif t == "fav":
            data.setdefault("favs", []).append({
                "id": _num(r.get("id")), "type": g("type"), "amount": _num(r.get("amount")),
                "asset": g("asset"), "to": g("to"), "topic": g("topic"), "note": g("note"),
            })
        elif t == "asset":
            data.setdefault("assets", []).append({
                "id": r.get("id") or "", "name": g("name"), "base": _num(r.get("base")), "color": r.get("color") or "",
            })
        elif t == "liab":
            data.setdefault("liabs", []).append({"id": r.get("id") or "", "name": g("name"), "amount": _num(r.get("amount"))})
        elif t == "topic":
            data.setdefault("topics", []).append({"name": g("name"), "color": r.get("color") or "", "kind": r.get("type") or ""})
    return {"updated": updated, "data": data}


def csv_to_remote(raw):
    text = raw.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    if rows and rows[0] and rows[0][0].strip() == "table":
        return csv_to_remote_legacy(raw)  # ไฟล์รูปแบบเก่า

    data, updated = {}, 0
    section, idx, want_header = None, {}, False
    seq = int(time.time() * 1000)  # ไว้สร้างรหัสให้แถวที่เพิ่มมือแล้วไม่มีรหัส

    for r in rows:
        if not any(c.strip() for c in r):
            continue
        head = r[0].strip()
        if head.startswith("■ ") and head[2:].strip() in SECTIONS:
            section, want_header = head[2:].strip(), True
            continue
        if want_header:
            idx = {h.strip(): i for i, h in enumerate(r)}
            want_header = False
            continue

        def g(name):
            i = idx.get(name)
            return _u(r[i]) if i is not None and i < len(r) else ""

        def ident(name=C_ID):
            nonlocal seq
            v = _num(g(name))
            if not v:
                seq += 1
                v = seq
            return v

        if section == S_META:
            if g("หัวข้อ") == "รหัสเวลาแก้ไข":
                updated = int(_num(g("ค่า")))

        elif section == S_SET:
            label, val = g("รายการ").strip(), g("ค่า")
            spec = SPEC_BY_LABEL.get(label)
            if spec:
                grp, key, _, kind, mp = spec
                v = _decode(val, kind, mp)
                if grp is None:
                    data["budget"] = v
                else:
                    data.setdefault(grp, {})[key] = v
            elif "." in label:
                grp, k = label.split(".", 1)
                if grp in ("stats", "settings"):
                    try:
                        data.setdefault(grp, {})[k] = json.loads(val)
                    except ValueError:
                        pass

        elif section == S_ENTRY:
            tp, amount, date, asset = TYPE_EN.get(g("ประเภท").strip()), _num(g("จำนวนเงิน")), g("วันที่").strip(), g("ที่เก็บ")
            if not tp or not (amount > 0) or not DATE_RE.match(date) or not asset:
                continue  # แถวที่กรอกไม่ครบ/ผิดรูปแบบ ข้ามไป กันหน้าเว็บพัง
            data.setdefault("entries", []).append({
                "id": ident(), "date": date, "type": tp, "amount": amount, "asset": asset,
                "to": g("โอนไปที่"), "topic": g("หัวข้อ"), "note": g("หมายเหตุ"),
            })

        elif section == S_FAV:
            tp, amount, asset = TYPE_EN.get(g("ประเภท").strip()), _num(g("จำนวนเงิน")), g("ที่เก็บ")
            if not tp or not (amount > 0) or not asset:
                continue
            data.setdefault("favs", []).append({
                "id": ident(), "type": tp, "amount": amount, "asset": asset,
                "to": g("โอนไปที่"), "topic": g("หัวข้อ"), "note": g("หมายเหตุ"),
            })

        elif section == S_ASSET:
            if g("ชื่อ"):
                data.setdefault("assets", []).append({
                    "id": g(C_ID) or f"x{ident('')}", "name": g("ชื่อ"), "base": _num(g("ยอดตั้งต้น")), "color": g("สี"),
                })

        elif section == S_LIAB:
            if g("ชื่อหนี้"):
                data.setdefault("liabs", []).append({
                    "id": g(C_ID) or f"l{ident('')}", "name": g("ชื่อหนี้"), "amount": _num(g("จำนวนเงิน")),
                })

        elif section == S_TOPIC:
            if g("ชื่อหัวข้อ"):
                data.setdefault("topics", []).append({
                    "name": g("ชื่อหัวข้อ"), "color": g("สี"), "kind": TYPE_EN.get(g("ประเภท").strip(), ""),
                })

    return {"updated": updated, "data": data}

def read_remote():
    """คืน (file_id, {"updated": ms, "data": {...}}) หรือ (None, None) ถ้ายังไม่มีไฟล์"""
    file_id, legacy = find_file_id(DATA_FILE_NAME), False
    if not file_id:
        if not file_id:
            return None, None
    resp = drive("GET", f"{DRIVE_API}/files/{file_id}", params={"alt": "media"})
    if resp.status_code != 200:
        raise drive_error("read", resp)
    try:
        if legacy:
            doc = json.loads(resp.content.decode("utf-8"))
            remote = {"updated": int(doc.get("updated", 0)), "data": doc.get("data") or {}}
        else:
            remote = csv_to_remote(resp.content)
    except (ValueError, TypeError, KeyError, csv.Error):
        raise DriveError("ไฟล์บน Drive อ่านไม่ได้")
    return (None if legacy else file_id), remote


def write_remote(file_id, updated, data):
    content = data_to_csv(updated, data)
    if file_id:
        resp = drive(
            "PATCH",
            f"{DRIVE_UPLOAD}/files/{file_id}",
            params={"uploadType": "media"},
            headers={"Content-Type": "text/csv; charset=UTF-8"},
            data=content,
        )
    else:
        boundary = f"mwboundary{int(time.time() * 1000)}"
        meta = json.dumps(
            {"name": DATA_FILE_NAME, "mimeType": "text/csv", "description": "ข้อมูลแอปเงินเดินได้ (แก้ด้วยมือไม่แนะนำ)"},
            ensure_ascii=False,
        )
        body = (
            f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n"
            f"--{boundary}\r\nContent-Type: text/csv; charset=UTF-8\r\n\r\n"
        ).encode("utf-8") + content + f"\r\n--{boundary}--".encode("utf-8")
        resp = drive(
            "POST",
            f"{DRIVE_UPLOAD}/files",
            params={"uploadType": "multipart"},
            headers={"Content-Type": f"multipart/related; boundary={boundary}"},
            data=body,
        )
    if resp.status_code not in (200, 201):
        raise drive_error("write", resp)


LIST_KEYS = {"entries", "assets", "liabs", "favs", "topics"}
DICT_KEYS = {"stats", "settings"}
ALLOWED_KEYS = LIST_KEYS | DICT_KEYS | {"budget"}


def valid_data(data):
    if not isinstance(data, dict) or not set(data) <= ALLOWED_KEYS:
        return False
    for k, v in data.items():
        if k in LIST_KEYS and not isinstance(v, list):
            return False
        if k in DICT_KEYS and not isinstance(v, dict):
            return False
        if k == "budget" and (isinstance(v, bool) or not isinstance(v, (int, float))):
            return False
    return True


# ---------------------------------------------------------------------------
# หน้าเว็บ
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    user = session["user"]
    return render_template("index.html", email=user["email"], uid=user["sub"])


@app.route("/login")
def login():
    if is_logged_in():
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/auth/google")
def auth_google():
    # access_type=offline เพื่อให้ได้ refresh token ไว้ต่ออายุสิทธิ์เข้า Drive
    # force=1 บังคับให้ขึ้นหน้าอนุญาตอีกครั้ง (ใช้เมื่อยังไม่เคยได้ refresh token)
    extra = {"access_type": "offline"}
    if request.args.get("force"):
        extra["prompt"] = "consent"
        session["forced_consent"] = True
    return oauth.google.authorize_redirect(os.environ["REDIRECT_URI"], **extra)


@app.route("/auth/callback")
def callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        return render_template("login.html", error="เข้าสู่ระบบไม่สำเร็จ ลองใหม่อีกครั้ง")

    info = token.get("userinfo") or {}
    sub, email = info.get("sub"), info.get("email")
    if not sub or not email:
        return render_template("login.html", error="อ่านข้อมูลบัญชี Google ไม่ได้ ลองใหม่อีกครั้ง")

    # ผู้ใช้อาจเอาติ๊ก Drive ออกบนหน้าอนุญาต ต้องมีสิทธินี้ถึงจะเก็บข้อมูลได้
    if DRIVE_SCOPE not in str(token.get("scope", "")).split():
        return render_template("login.html", error="ต้องอนุญาตให้แอปเก็บไฟล์ใน Google Drive จึงจะใช้งานได้ ลองใหม่แล้วติ๊กอนุญาตทุกข้อ")

    refresh_token = token.get("refresh_token")
    if refresh_token:
        save_refresh_token(sub, refresh_token)
        session.pop("forced_consent", None)
    elif not get_refresh_token(sub):
        if session.pop("forced_consent", False):
            return render_template("login.html", error="ไม่ได้รับสิทธิ์ต่ออายุจาก Google ลองใหม่อีกครั้ง")
        return redirect(url_for("auth_google", force=1))

    session.pop("forced_consent", None)
    session["user"] = {"email": email, "name": info.get("name", ""), "sub": sub}
    session["gtoken"] = {
        "access_token": token["access_token"],
        "expires_at": int(token.get("expires_at") or time.time() + int(token.get("expires_in", 3600))),
    }
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# API ข้อมูล: อ่าน/เขียนไฟล์ money-data.json ใน Google Drive ของผู้ใช้ที่ล็อกอินอยู่
# ---------------------------------------------------------------------------
@app.route("/api/data", methods=["GET", "PUT", "POST"])  # POST ไว้ให้ sendBeacon ตอนปิดแท็บ
@api_login_required
def api_data():
    try:
        if request.method == "GET":
            _, remote = read_remote()
            if remote is None:
                return jsonify(exists=False)
            return jsonify(exists=True, updated=remote["updated"], data=remote["data"])

        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not valid_data(body.get("data")):
            return jsonify(error="bad_request"), 400
        base, force = body.get("base"), bool(body.get("force"))

        file_id, remote = read_remote()
        # กันเขียนทับข้อมูลที่เครื่องอื่นเพิ่งแก้: ถ้าฐานที่เครื่องนี้เห็นไม่ตรงกับบน Drive ให้ตอบ 409
        if remote is not None and not force and base != remote["updated"]:
            return jsonify(error="conflict", remote=remote), 409

        updated = int(time.time() * 1000)
        if remote is not None:
            updated = max(updated, remote["updated"] + 1)
        write_remote(file_id, updated, body["data"])
        return jsonify(ok=True, updated=updated)

    except Reauth:
        return jsonify(error="reauth"), 401
    except DriveError as e:
        app.logger.warning("drive error: %s", e)
        return jsonify(error="drive", detail=str(e)), 502
    except requests.RequestException as e:
        app.logger.warning("drive network error: %s", e)
        return jsonify(error="drive", detail="เซิร์ฟเวอร์เชื่อมต่อ Google ไม่ได้: " + type(e).__name__), 502
    except Exception as e:  # ข้อผิดพลาดอื่นในเซิร์ฟเวอร์ ให้หน้าเว็บเห็นสาเหตุแทนหน้า 500 เปล่าๆ
        app.logger.exception("api_data failed")
        return jsonify(error="server", detail=type(e).__name__ + ": " + str(e)[:200]), 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
