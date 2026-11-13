import os
import sys
import uuid
import json
import base64
import sqlite3
import subprocess
import time
import threading
import socket
import struct
import shutil
import urllib.parse
from datetime import datetime, timedelta
from urllib.parse import urlsplit, quote
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session

try:
    import telebot
except ImportError:
    telebot = None

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = os.environ.get("SECRET_KEY", "vega-rail-secret-key-change-me")

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin")

BRAND = "VEGA"  # نام برند به شکل ASCII (برای نام کانفیگ‌های سازگار)
BRAND_BOLD = "𝗩𝗘𝗚𝗔"  # فرم بولد یونیکد نام برند در remark کانفیگ‌ها

XRAY_PORT = 10000
TROJAN_PORT = 10001
VMESS_PORT = 10002
XRAY_API_PORT = 10085
FLASK_PORT = 5000

DB_PATH = "users.db"
XRAY_CONFIG_PATH = "xray_config.json"
NGINX_CONFIG_PATH = "nginx.conf"

ONLINE_USERS = {}
ONLINE_THRESHOLD = 90

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            uuid TEXT UNIQUE NOT NULL,
            quota_gb REAL DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            expire_days INTEGER DEFAULT 30,
            created_at TEXT,
            enabled INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_setting(key, default=""):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default

def set_setting(key, value):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print("Error saving setting:", e)
        return False

def get_admin_credentials():
    env_user = os.environ.get("ADMIN_USER")
    env_pass = os.environ.get("ADMIN_PASS")

    if env_user is not None and env_pass is not None:
        return env_user, env_pass

    settings_file = "panel_settings.json"

    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            username = data.get("username", "admin")
            password = data.get("password", "admin")

            return username, password

        except Exception:
            pass

    return "admin", "admin"

def save_admin_credentials(username, password):
    settings_file = "panel_settings.json"

    data = {
        "username": username,
        "password": password
    }

    with open(settings_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_all_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_user_active(user):
    """بررسی فعال بودن کاربر بر اساس ترافیک، زمان و وضعیت کلی"""
    if user["enabled"] == 0:
        return False, "disabled"

    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        if elapsed_days >= user["expire_days"]:
            return False, "expired"
    except Exception:
        pass

    used_gb = user["used_bytes"] / (1024 ** 3)
    if user["quota_gb"] > 0 and used_gb >= user["quota_gb"]:
        return False, "limit_exceeded"

    return True, "active"

def enrich_user(u):
    try:
        created_dt = datetime.fromisoformat(u["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        days_left = max(0, u["expire_days"] - elapsed_days)
    except Exception:
        days_left = u["expire_days"]

    used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
    quota_gb = round(float(u["quota_gb"]), 2)

    if quota_gb > 0:
        percent = min(100, round((used_gb / quota_gb) * 100, 1))
    else:
        percent = 0

    active_state, reason = is_user_active(u)

    u["used_gb"] = used_gb
    u["days_left"] = days_left
    u["percent"] = percent
    u["is_expired"] = days_left <= 0 or reason == "expired"
    u["is_limit_exceeded"] = reason == "limit_exceeded"
    u["is_active"] = active_state
    u["created_date"] = u["created_at"][:10] if u.get("created_at") else ""
    u["is_online"] = is_user_online(u["name"])

    return u

def is_user_online(name):
    last_seen = ONLINE_USERS.get(name, 0)
    return (time.time() - last_seen) < ONLINE_THRESHOLD

def build_xray_config():
    users = get_all_users()

    vless_clients = []
    trojan_clients = []
    vmess_clients = []

    for u in users:
        # فقط کاربرانی که واقعاً فعال هستند داخل کانفیگ Xray ریخته می‌شوند
        active, _ = is_user_active(u)
        if not active:
            continue

        vless_clients.append({"id": u["uuid"], "email": u["name"], "level": 0})
        # در تروجان رمز عبور همان UUID کاربر است تا همه پروتکل‌ها یک هویت داشته باشند
        trojan_clients.append({"password": u["uuid"], "email": u["name"], "level": 0})
        vmess_clients.append({"id": u["uuid"], "email": u["name"], "level": 0})

    if not vless_clients:
        fallback_id = str(uuid.uuid4())
        vless_clients.append({"id": fallback_id, "email": "default_user", "level": 0})
        trojan_clients.append({"password": fallback_id, "email": "default_user", "level": 0})
        vmess_clients.append({"id": fallback_id, "email": "default_user", "level": 0})

    config = {
        "log": {
            "loglevel": "warning"
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        },
        "inbounds": [
            {
                "tag": "api",
                "port": XRAY_API_PORT,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            },
            {
                "tag": "vless-in",
                "port": XRAY_PORT,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": vless_clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/ws"
                    }
                }
            },
            {
                "tag": "trojan-in",
                "port": TROJAN_PORT,
                "listen": "127.0.0.1",
                "protocol": "trojan",
                "settings": {
                    "clients": trojan_clients
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/tr"
                    }
                }
            },
            {
                "tag": "vmess-in",
                "port": VMESS_PORT,
                "listen": "127.0.0.1",
                "protocol": "vmess",
                "settings": {
                    "clients": vmess_clients
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/vm"
                    }
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                }
            ]
        }
    }

    with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def restart_xray():
    build_xray_config()
    try:
        subprocess.run(["pkill", "-9", "-f", "xray"], check=False)
        time.sleep(0.5)
    except Exception:
        pass

    try:
        xray_bin = "/usr/local/bin/xray/xray"
        if not os.path.exists(xray_bin):
            xray_bin = "xray"

        subprocess.Popen(
            [xray_bin, "run", "-c", XRAY_CONFIG_PATH],
            stdout=sys.stdout,
            stderr=sys.stderr
        )
    except Exception as e:
        print("Xray start error:", e)

def xray_query_stats():
    stats = {}
    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

    try:
        result = subprocess.run(
            [
                xray_bin,
                "api",
                "statsquery",
                f"--server=127.0.0.1:{XRAY_API_PORT}",
                "-pattern=user>>>",
                "-reset=true"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return stats

        data = json.loads(result.stdout)
        stat_list = data.get("stat", [])

        for item in stat_list:
            name = item.get("name", "")
            value = int(item.get("value", 0))

            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user":
                user_email = parts[1]

                if user_email not in stats:
                    stats[user_email] = 0

                stats[user_email] += value

    except Exception:
        pass

    return stats

def xray_reset_user_stats(user_email):
    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

    try:
        for direction in ["uplink", "downlink"]:
            subprocess.run(
                [
                    xray_bin,
                    "api",
                    "statsquery",
                    f"--server=127.0.0.1:{XRAY_API_PORT}",
                    "-reset=true",
                    f"-pattern=user>>>{user_email}>>>traffic>>>{direction}"
                ],
                capture_output=True,
                timeout=3
            )
    except Exception:
        pass

PREVIOUS_STATS = {}

def stats_collector():
    global PREVIOUS_STATS

    while True:
        try:
            time.sleep(15)

            stats = xray_query_stats()

            if not stats:
                continue

            conn = get_db()
            c = conn.cursor()

            need_restart = False

            for user_email, total_bytes in stats.items():
                if total_bytes <= 0:
                    continue

                c.execute(
                    "UPDATE users SET used_bytes = used_bytes + ? WHERE name = ?",
                    (total_bytes, user_email)
                )

                ONLINE_USERS[user_email] = time.time()

                c.execute(
                    "SELECT id, quota_gb, used_bytes, enabled, created_at, expire_days FROM users WHERE name = ?",
                    (user_email,)
                )

                row = c.fetchone()

                if row and row["enabled"] == 1:
                    # دیگر کاربر را در دیتابیس کلاً غیرفعال نمی‌کنیم (تا سابسکریپشن قطع نشود)
                    # فقط وضعیت فعال بودن واقعی او را می‌سنجیم و در صورت لزوم Xray را ریستارت می‌کنیم تا قطع شود
                    active, reason = is_user_active(dict(row))
                    if not active:
                        need_restart = True
                        print(f"[QUOTA/TIME] User '{user_email}' is no longer active ({reason}). Disabling from Xray.")

            conn.commit()
            conn.close()

            if need_restart:
                restart_xray()

        except Exception as e:
            print("Stats collector error:", e)

def start_stats_collector():
    t = threading.Thread(target=stats_collector, daemon=True)
    t.start()

def start_nginx():
    port = os.environ.get("PORT", "8080")

    nginx_conf = f"""
pid /run/nginx.pid;
error_log /dev/stderr warn;
events {{
    worker_connections 1024;
}}
http {{
    access_log /dev/stdout;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
    }}
    server {{
        listen {port};
        server_name _;
        location ~ ^/ws {{
            proxy_redirect off;
            rewrite ^/ws.*$ /ws break;
            proxy_pass http://127.0.0.1:{XRAY_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location ~ ^/tr {{
            proxy_redirect off;
            rewrite ^/tr.*$ /tr break;
            proxy_pass http://127.0.0.1:{TROJAN_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location ~ ^/vm {{
            proxy_redirect off;
            rewrite ^/vm.*$ /vm break;
            proxy_pass http://127.0.0.1:{VMESS_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location / {{
            proxy_pass http://127.0.0.1:{FLASK_PORT};
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}
}}
"""

    with open(NGINX_CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(nginx_conf)

    try:
        subprocess.run(["pkill", "-9", "-f", "nginx"], check=False)
        time.sleep(0.3)
    except Exception:
        pass

    subprocess.Popen([
        "nginx",
        "-c",
        os.path.abspath(NGINX_CONFIG_PATH),
        "-g",
        "daemon off;"
    ])

def _enc(value):
    return urllib.parse.quote(str(value), safe="")


def _vless_link(uuid_str, host, port, path, remark, tls=True, alpn=None, fp=None):
    """لینک VLESS در قالب استاندارد و «محافظه‌کارانه».

    نکته: پارامترهای insecure / allowInsecure / alpn عمداً حذف شده‌اند.
    روی وب‌سوکت (WS) تعیین alpn=h2 اشتباه است و بعضی پارسرهای سخت‌گیر
    (v2rayNG) کل ساب را به‌خاطر یک پارامتر غیرمنتظره رد می‌کنند.
    """
    params = ["type=ws"]

    if tls:
        params += ["security=tls", "encryption=none"]
    else:
        params += ["security=none", "encryption=none"]

    params.append(f"path={_enc(path)}")
    params.append(f"host={_enc(host)}")

    if tls:
        params.append(f"sni={_enc(host)}")
        if fp:
            params.append(f"fp={_enc(fp)}")

    return f"vless://{uuid_str}@{host}:{port}?" + "&".join(params) + f"#{_enc(remark)}"


def _trojan_link(uuid_str, host, port, path, remark, alpn=None, fp=None, tls=True):
    """لینک تروجان، همان قالب محافظه‌کارانه (بدون alpn و allowInsecure)."""
    params = ["type=ws"]

    if tls:
        params += ["security=tls"]
    else:
        params += ["security=none"]

    params.append(f"path={_enc(path)}")
    params.append(f"host={_enc(host)}")

    if tls:
        params.append(f"sni={_enc(host)}")
        if fp:
            params.append(f"fp={_enc(fp)}")

    return f"trojan://{uuid_str}@{host}:{port}?" + "&".join(params) + f"#{_enc(remark)}"


def _vmess_link(uuid_str, host, port, path, remark, alpn=None, fp=None, tls=True):
    """VMess فقط با کلیدهای پایه؛ کلیدهای اضافی (alpn) حذف شده‌اند."""
    obj = {
        "v": "2",
        "ps": remark,
        "add": host,
        "port": str(port),
        "id": uuid_str,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls" if tls else "",
        "sni": host if tls else "",
    }

    if tls and fp:
        obj["fp"] = fp

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode()


def make_all_configs(user, host, port=443, tls=True, ascii_names=False):
    """۸ کانفیگ برای هر کاربر: ۴ عدد VLESS، ۲ عدد Trojan، ۲ عدد VMess.

    هر سه پروتکل سمت سرور inbound جدا دارند (XRAY_PORT / TROJAN_PORT / VMESS_PORT)
    و از طریق nginx روی مسیرهای /ws ، /tr و /vm به بیرون سرو می‌شوند.
    """
    u_uuid = user["uuid"]
    name = user["name"]

    def remark(number):
        # فقط برند + شمارهٔ کانفیگ + ایموجی رعد
        if ascii_names:
            # نسخهٔ ASCII خالص برای v2rayNG اندروید (برخی نسخه‌ها با نام‌های
            # یونیکد/ایموجی مشکل دارند)
            return f"{BRAND} | {number} | {name}"
        return f"⚡ {BRAND_BOLD} | {number} | {name}"

    # (شماره، تگ، نوع، پارامترها)
    plan = [
        (1, "VLESS · WS", "vless",
         {"port": port, "path": f"/ws/{u_uuid}", "fp": "chrome"}),
        (2, "VLESS · ED2560", "vless",
         {"port": port, "path": f"/ws/{u_uuid}?ed=2560", "fp": "firefox"}),
        (3, "VLESS · ED2048", "vless",
         {"port": port, "path": f"/ws/{u_uuid}?ed=2048", "fp": "safari"}),
        (4, "VLESS · ALT", "vless",
         {"port": port, "path": f"/ws/{u_uuid}", "fp": "android"}),
        (5, "TROJAN · WS", "trojan",
         {"port": port, "path": f"/tr/{u_uuid}", "fp": "chrome"}),
        (6, "TROJAN · ED2048", "trojan",
         {"port": port, "path": f"/tr/{u_uuid}?ed=2048", "fp": "firefox"}),
        (7, "VMESS · WS", "vmess",
         {"port": port, "path": f"/vm/{u_uuid}", "fp": "chrome"}),
        (8, "VMESS · ED2048", "vmess",
         {"port": port, "path": f"/vm/{u_uuid}?ed=2048", "fp": "firefox"}),
    ]

    desc = {
        "vless": "اتصال پایدار روی هسته VLESS با وب‌سوکت و TLS",
        "trojan": "اتصال روی پروتکل تروجان با وب‌سوکت و TLS، مناسب شبکه‌های سخت‌گیر",
        "vmess": "اتصال روی پروتکل VMess با وب‌سوکت و TLS، گزینه جایگزین",
    }

    configs = []
    for number, tag, kind, p in plan:
        text = remark(number)
        # اثر انگشت (fp) فقط در حالت TLS معنا دارد
        alpn = None
        fp = p.get("fp") if tls else None
        if kind == "vless":
            link = _vless_link(
                u_uuid, host, p["port"], p["path"], text,
                tls=tls, alpn=alpn, fp=fp,
            )
        elif kind == "trojan":
            link = _trojan_link(
                u_uuid, host, p["port"], p["path"], text,
                alpn=alpn, fp=fp, tls=tls,
            )
        else:
            link = _vmess_link(
                u_uuid, host, p["port"], p["path"], text,
                alpn=alpn, fp=fp, tls=tls,
            )

        configs.append({
            "title": (f"{BRAND} | {number}" if ascii_names else f"⚡ {BRAND_BOLD} | {number}"),
            "desc": desc[kind],
            "tag": tag,
            "protocol": kind,
            "config": link,
        })

    return configs


# نام قدیمی برای سازگاری با کدهای قبلی
make_all_vless_configs = make_all_configs


def make_fake_config(reason, user, host, port=443, tls=True):
    """تولید کانکشن غیرفعال (نمایشی) جهت اطلاع‌رسانی به کاربر نهایی در نرم‌افزارش"""
    u_uuid = str(uuid.uuid4())
    name = user["name"]
    
    if reason == "limit_exceeded":
        remark = f"⛔️ Traffic Limit Exceeded | {name}"
        desc = "حجم ترافیک مجاز شما به اتمام رسیده است. جهت تمدید اقدام کنید."
    elif reason == "expired":
        remark = f"⛔️ Subscription Expired | {name}"
        desc = "زمان اشتراک شما به پایان رسیده است. جهت تمدید اقدام کنید."
    else:
        remark = f"⛔️ Service Disabled | {name}"
        desc = "سرویس شما توسط ادمین غیرفعال شده است."
        
    remark_encoded = urllib.parse.quote(remark)
    security = "tls" if tls else "none"
    sni = f"&sni={host}" if tls else ""

    config_str = (
        f"vless://{u_uuid}@{host}:{port}"
        f"?path=%2Fws%2Fdummy"
        f"&security={security}"
        f"&encryption=none"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"{sni}"
        f"#{remark_encoded}"
    )
    return [{
        "title": remark,
        "desc": desc,
        "tag": "Alert",
        "config": config_str
    }]

def get_subscription_header(user):
    """تولید هدر استاندارد مانیتورینگ حجم برای نمایش بالای نرم‌افزار کاربر"""
    used = int(user["used_bytes"])
    total = int(float(user["quota_gb"]) * (1024 ** 3))
    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        expire_dt = created_dt + timedelta(days=int(user["expire_days"]))
        expire_ts = int(expire_dt.timestamp())
    except Exception:
        expire_ts = 0
    return f"upload=0; download={used}; total={total}; expire={expire_ts}"


# ------------------------------------------------------------------
# SYSTEM METRICS (CPU / RAM / DISK)
# ------------------------------------------------------------------

_CPU_LOCK = threading.Lock()
_CPU_PREV = {"total": None, "idle": None}


def _cpu_times():
    """(total, idle) jiffies از /proc/stat"""
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()
        vals = [int(x) for x in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return sum(vals), idle
    except Exception:
        return None, None


def cpu_percent():
    """درصد مصرف CPU بر اساس اختلاف دو نمونه"""
    total, idle = _cpu_times()
    if total is None:
        return None, None

    with _CPU_LOCK:
        prev_total, prev_idle = _CPU_PREV["total"], _CPU_PREV["idle"]
        _CPU_PREV["total"], _CPU_PREV["idle"] = total, idle

    if prev_total is None or total <= prev_total:
        # اولین فراخوانی: یک نمونه‌برداری کوتاه
        time.sleep(0.15)
        total2, idle2 = _cpu_times()
        if total2 is None or total2 <= total:
            return 0.0, os.cpu_count()
        pct = 100.0 * (1 - (idle2 - idle) / float(total2 - total))
        with _CPU_LOCK:
            _CPU_PREV["total"], _CPU_PREV["idle"] = total2, idle2
        return round(max(0.0, min(100.0, pct)), 1), os.cpu_count()

    pct = 100.0 * (1 - (idle - prev_idle) / float(total - prev_total))
    return round(max(0.0, min(100.0, pct)), 1), os.cpu_count()


def memory_info():
    info = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                info[key.strip()] = int(rest.split()[0]) * 1024  # kB -> B
    except Exception:
        return None

    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable") or (
        info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
    )
    used = max(0, total - avail)
    pct = (used / total * 100.0) if total else 0.0
    return {
        "percent": round(pct, 1),
        "used_gb": round(used / (1024 ** 3), 2),
        "total_gb": round(total / (1024 ** 3), 2),
    }


def disk_info():
    try:
        du = shutil.disk_usage("/")
    except Exception:
        return None
    pct = (du.used / du.total * 100.0) if du.total else 0.0
    return {
        "percent": round(pct, 1),
        "used_gb": round(du.used / (1024 ** 3), 1),
        "total_gb": round(du.total / (1024 ** 3), 1),
    }


def uptime_seconds():
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0



# ------------------------------------------------------------------
# آدرس عمومی اشتراک (هاست / پورت / TLS)
# ------------------------------------------------------------------

TLS_PORTS = {443, 8443, 2053, 2083, 2087, 2096}


def resolve_public_endpoint():
    """هاست، پورت و وضعیت TLS عمومیِ لینک‌های ساب را تعیین می‌کند.

    پیش‌فرض عمداً «443 + TLS روشن» است، چون تقریباً همهٔ نصب‌های واقعی پشت
    یک reverse proxy یا CDN روی 443 سرو می‌شوند؛ حتی اگر خودِ پنل روی
    http://…:8080 باز شود، لینک کلاینت نباید روی پورت 80 و بدون TLS ساخته شود.

    ترتیب اولویت:
      1) SUB_TLS  (env) یا تنظیمات sub_tls   → روشن/خاموشِ TLS
      2) SUB_PORT (env) یا تنظیمات sub_port  → پورت عمومی
      3) هدرهای X-Forwarded-Proto/Host       → اگر پشت پروکسی با TLS باشید
      4) پیش‌فرض: پورت 443 و TLS روشن
    """
    host = request.host.split(":")[0]

    def _clean(value):
        return (value or "").strip()

    forced_tls = _clean(os.environ.get("SUB_TLS") or get_setting("sub_tls", "")).lower()
    forced_port = _clean(os.environ.get("SUB_PORT") or get_setting("sub_port", ""))

    # --- 1) وضعیت TLS -------------------------------------------------
    if forced_tls in ("1", "true", "yes", "on", "tls"):
        tls = True
    elif forced_tls in ("0", "false", "no", "off", "none", "notls"):
        tls = False
    else:
        tls = None  # خودکار

    # --- 2) پورت عمومی ------------------------------------------------
    port = int(forced_port) if forced_port.isdigit() else None

    scheme = (
        request.headers.get("X-Forwarded-Proto")
        or request.headers.get("X-Forwarded-Scheme")
        or request.scheme
        or "http"
    ).split(",")[0].strip().lower()

    req_port = request.host.split(":")[1] if ":" in request.host else ""
    req_port = req_port if req_port.isdigit() else None

    if port is not None:
        # پورت دستی تعیین شده؛ اگر TLS هم دستی نیامده باشد از روی پورت حدس می‌زنیم
        if tls is None:
            tls = port in TLS_PORTS
    elif tls is False:
        # صریحاً «بدون TLS» خواسته شده → همان پورتی که پنل رویش باز است
        port = int(req_port) if req_port else 80
    else:
        # خودکار یا TLS روشن → 443 (مگر اینکه درخواست روی یک پورت TLS غیراستاندارد باشد)
        if tls is None and req_port and int(req_port) in TLS_PORTS and scheme == "https":
            port = int(req_port)
        else:
            port = 443
        tls = True

    return host, port, tls


def build_sub_url(user_uuid):
    """لینک خام اشتراک (چیزی که باید در v2rayNG وارد شود)"""
    base = request.host_url.rstrip("/")
    return f"{base}/sub/{user_uuid}"


@app.route("/")
def home():
    if "admin" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        current_username, current_password = get_admin_credentials()

        if username == current_username and password == current_password:
            session["admin"] = True
            return redirect(url_for("dashboard"))

        ep_host, ep_port, ep_tls = _login_endpoint()

        return render_template(
            "login.html",
            error="نام کاربری یا رمز عبور اشتباه است!",
            endpoint_host=ep_host,
            endpoint_port=ep_port,
            endpoint_tls=ep_tls,
        )

    ep_host, ep_port, ep_tls = _login_endpoint()

    return render_template(
        "login.html",
        error=None,
        endpoint_host=ep_host,
        endpoint_port=ep_port,
        endpoint_tls=ep_tls,
    )


def _login_endpoint():
    """مقصد عمومی را برای نمایش در صفحهٔ ورود برمی‌گرداند (بدون خطا در نبودِ تنظیمات)."""
    try:
        return resolve_public_endpoint()
    except Exception:
        host = (request.host or "").split(":")[0]
        return host, 443, True

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))

    users = get_all_users()

    total_gb = sum(u["quota_gb"] for u in users)
    total_used = sum(u["used_bytes"] for u in users) / (1024 ** 3)
    active_count = sum(1 for u in users if is_user_active(u)[0])

    used_pct = round((total_used / total_gb) * 100) if total_gb else 0
    used_pct = max(0, min(100, used_pct))
    remaining_gb = round(max(total_gb - total_used, 0), 2)

    # سه باند فشار سهمیه: >70% ، 40-70% ، <40%
    bands = {
        "high": {"n": 0, "gb": 0.0},
        "mid":  {"n": 0, "gb": 0.0},
        "low":  {"n": 0, "gb": 0.0},
    }

    enriched = []

    for u in users:
        quota = u["quota_gb"] or 0
        used = u["used_bytes"] / (1024 ** 3)
        pct = (used / quota * 100) if quota else 0

        key = "high" if pct >= 70 else ("mid" if pct >= 40 else "low")
        bands[key]["n"] += 1
        bands[key]["gb"] += used

        enriched.append({
            "name": u["name"],
            "used_gb": round(used, 2),
            "quota_gb": quota,
            "pct": max(0, min(100, round(pct))),
        })

    band_gb_total = sum(b["gb"] for b in bands.values())
    band_n_total = sum(b["n"] for b in bands.values()) or 1

    for key, band in bands.items():
        band["gb"] = round(band["gb"], 2)

        if band_gb_total > 0:
            band["pct"] = round(band["gb"] / band_gb_total * 100)
        else:
            band["pct"] = round(band["n"] / band_n_total * 100)

    top_users = sorted(enriched, key=lambda x: x["used_gb"], reverse=True)[:5]

    return render_template(
        "dashboard.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2),
        used_pct=used_pct,
        remaining_gb=remaining_gb,
        bands=bands,
        top_users=top_users,
        more_users=max(len(users) - len(top_users), 0),
        avg_used=round(total_used / len(users), 2) if users else 0,
    )


@app.route("/api/system")
def api_system():
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    cpu_pct, cores = cpu_percent()
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        load = [0, 0, 0]

    return jsonify({
        "status": "success",
        "cpu": {
            "percent": cpu_pct if cpu_pct is not None else 0,
            "cores": cores or 1,
            "load": load,
        },
        "ram": memory_info() or {"percent": 0, "used_gb": 0, "total_gb": 0},
        "disk": disk_info() or {"percent": 0, "used_gb": 0, "total_gb": 0},
        "uptime": uptime_seconds(),
        "host": socket.gethostname(),
    })


@app.route("/users")
def users_page():
    if "admin" not in session:
        return redirect(url_for("login"))

    raw_users = get_all_users()
    users = [enrich_user(u) for u in raw_users]

    total_gb = sum(u["quota_gb"] for u in raw_users)
    total_used = sum(u["used_bytes"] for u in raw_users) / (1024 ** 3)
    active_count = sum(1 for u in users if u["is_active"])
    disabled_count = sum(1 for u in users if u["enabled"] == 0)
    expired_count = sum(1 for u in users if u["is_expired"] or u["is_limit_exceeded"])
    online_count = sum(1 for u in users if u["is_online"])

    return render_template(
        "users.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        disabled_users=disabled_count,
        expired_users=expired_count,
        online_users=online_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2)
    )

@app.route("/api/online_users")
def api_online_users():
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    raw_users = get_all_users()
    online = []

    for u in raw_users:
        if is_user_online(u["name"]):
            last_seen = ONLINE_USERS.get(u["name"], 0)
            seconds_ago = int(time.time() - last_seen)

            online.append({
                "id": u["id"],
                "name": u["name"],
                "used_gb": round(u["used_bytes"] / (1024 ** 3), 2),
                "quota_gb": u["quota_gb"],
                "seconds_ago": seconds_ago
            })

    return jsonify({
        "status": "success",
        "count": len(online),
        "users": online
    })

@app.route("/settings")
def settings():
    if "admin" not in session:
        return redirect(url_for("login"))

    username, _ = get_admin_credentials()
    tg_token = get_setting("telegram_token", "")
    tg_admin_id = get_setting("telegram_admin_id", "")

    sub_port = get_setting("sub_port", "")
    sub_tls = get_setting("sub_tls", "")

    try:
        det_host, det_port, det_tls = resolve_public_endpoint()
    except Exception:
        det_host, det_port, det_tls = "", 443, True

    return render_template(
        "settings.html",
        current_username=username,
        telegram_token=tg_token,
        telegram_admin_id=tg_admin_id,
        sub_port=sub_port,
        sub_tls=sub_tls,
        det_host=det_host,
        det_port=det_port,
        det_tls=det_tls
    )

@app.route("/api/settings", methods=["POST"])
def update_settings():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    if action == "telegram":
        tg_token = data.get("telegram_token", "").strip()
        tg_admin_id = data.get("telegram_admin_id", "").strip()

        try:
            set_setting("telegram_token", tg_token)
            set_setting("telegram_admin_id", tg_admin_id)
            return jsonify({"status": "success", "message": "تنظیمات ربات تلگرام با موفقیت ثبت شد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "endpoint":
        sub_port = str(data.get("sub_port", "")).strip()
        sub_tls = str(data.get("sub_tls", "")).strip().lower()

        if sub_port and not sub_port.isdigit():
            return jsonify({"status": "error", "message": "پورت باید عدد باشد"}), 400

        if sub_port and not (0 < int(sub_port) < 65536):
            return jsonify({"status": "error", "message": "پورت باید بین ۱ و ۶۵۵۳۵ باشد"}), 400

        if sub_tls not in ("", "1", "0"):
            return jsonify({"status": "error", "message": "مقدار TLS نامعتبر است"}), 400

        try:
            set_setting("sub_port", sub_port)
            set_setting("sub_tls", sub_tls)
            return jsonify({"status": "success", "message": "تنظیمات پورت و TLS لینک ساب ذخیره شد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "security":
        new_username = data.get("username", "").strip()
        new_password = data.get("password", "")
        current_password = data.get("current_password", "")

        if not new_username:
            return jsonify({"status": "error", "message": "نام کاربری جدید الزامی است"}), 400

        if not new_password:
            return jsonify({"status": "error", "message": "رمز عبور جدید الزامی است"}), 400

        username, password = get_admin_credentials()

        if current_password != password:
            return jsonify({"status": "error", "message": "رمز عبور فعلی اشتباه است"}), 400

        if len(new_username) < 3:
            return jsonify({"status": "error", "message": "نام کاربری حداقل باید ۳ کاراکتر باشد"}), 400

        if len(new_password) < 4:
            return jsonify({"status": "error", "message": "رمز عبور حداقل باید ۴ کاراکتر باشد"}), 400

        try:
            save_admin_credentials(new_username, new_password)
            session.pop("admin", None)
            return jsonify({"status": "success", "message": "اطلاعات ورود تغییر کرد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "error", "message": "درخواست نامعتبر"}), 400

@app.route("/api/add_user", methods=["POST"])
def add_user():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.json or {}

    name = data.get("name", "").strip()

    try:
        quota = float(data.get("quota", 30))
        days = int(data.get("days", 30))
    except Exception:
        return jsonify({"status": "error", "message": "حجم یا تعداد روز نامعتبر است"}), 400

    if not name:
        return jsonify({"status": "error", "message": "نام کاربر الزامی است"}), 400

    if quota <= 0:
        return jsonify({"status": "error", "message": "حجم باید بیشتر از صفر باشد"}), 400

    if days <= 0:
        return jsonify({"status": "error", "message": "تعداد روز باید بیشتر از صفر باشد"}), 400

    user_uuid = str(uuid.uuid4())

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            """
            INSERT INTO users
            (name, uuid, quota_gb, expire_days, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, user_uuid, quota, days, datetime.now().isoformat())
        )

        conn.commit()
        conn.close()

        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ساخته شد"})

    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "این نام کاربری قبلاً وجود دارد"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    data = request.get_json(silent=True) or {}

    try:
        new_quota = float(data.get("quota_gb", 0))
        new_days = int(data.get("expire_days", 0))
    except Exception:
        return jsonify({"status": "error", "message": "مقادیر نامعتبر"}), 400

    if new_quota <= 0 or new_days <= 0:
        return jsonify({"status": "error", "message": "حجم و روز باید بیشتر از صفر باشند"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            "UPDATE users SET quota_gb=?, expire_days=? WHERE id=?",
            (new_quota, new_days, user_id)
        )

        conn.commit()
        conn.close()

        # بازسازی هسته چون امکان دارد کاربر ویرایش‌شده تمدید حجم شده باشد و باید دوباره فعال شود
        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ویرایش شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/reset_user/<int:user_id>", methods=["POST"])
def reset_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT name FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

        if row:
            xray_reset_user_stats(row["name"])

        c.execute(
            "UPDATE users SET used_bytes=0, created_at=? WHERE id=?",
            (datetime.now().isoformat(), user_id)
        )

        conn.commit()
        conn.close()

        # بازسازی فایل کانفیگ برای فعال شدن مجدد کاربر قطع شده در Xray
        restart_xray()

        return jsonify({"status": "success", "message": "ترافیک کاربر صفر شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "message": "کاربر با موفقیت حذف شد"})

@app.route("/api/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT enabled FROM users WHERE id=?", (user_id,))

    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    new_val = 0 if row[0] == 1 else 1

    c.execute("UPDATE users SET enabled=? WHERE id=?", (new_val, user_id))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "new_state": new_val})

@app.route("/api/user_config/<int:user_id>")
def user_config(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    host, port, tls = resolve_public_endpoint()

    configs = make_all_configs(dict(user), host, port=port, tls=tls)

    sub_link = build_sub_url(user["uuid"])

    return jsonify({
        "status": "success",
        "configs": configs,
        "sub": sub_link,
        "sub_v2rayng": sub_link + "/v2rayng",
        "user": dict(user)
    })

CLIENT_UA_KEYWORDS = [
    "v2ray", "v2rayng", "xray", "clash", "sing-box", "singbox", "hiddify",
    "nekobox", "nekoray", "streisand", "foxray", "shadowrocket", "v2box",
    "quantumult", "surfboard", "kitsunebi", "okhttp", "dart", "go-http",
    "python-requests", "curl", "wget", "axios",
]

BROWSER_UA_KEYWORDS = ["mozilla", "chrome", "safari", "firefox", "edg/", "opr/", "opera"]


def _is_client_ua(ua):
    ua = (ua or "").lower()
    if any(k in ua for k in CLIENT_UA_KEYWORDS):
        return True
    return not any(k in ua for k in BROWSER_UA_KEYWORDS)


def _build_subscription_payload(user_dict, host, port, tls, ascii_names=False):
    active, reason = is_user_active(user_dict)
    if active:
        configs = make_all_configs(user_dict, host, port=port, tls=tls, ascii_names=ascii_names)
    else:
        configs = make_fake_config(reason, user_dict, host, port=port, tls=tls)

    links = []

    for item in configs:
        link = (item.get("config") or "").strip()

        # اعتبارسنجی سخت‌گیرانه: بعضی کلاینت‌ها (v2rayNG) با یک خط خراب
        # کل ساب را رد می‌کنند، پس خط‌های ناسالم اصلاً فرستاده نمی‌شوند.
        try:
            parts = urlsplit(link)
            ok = parts.scheme in ("vless", "vmess", "trojan") and bool(parts.netloc)
        except Exception:
            ok = False

        if not ok:
            app.logger.warning("sub: config line skipped (invalid URI): %s", link[:80])
            continue

        if any(ch.isspace() for ch in link.split("#")[0]):
            link = link.replace(" ", "%20")
            item["config"] = link

        links.append(link)

    raw_text = "\n".join(links)
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode()
    user_dict["_raw_text"] = raw_text
    return configs, encoded


def _raw_subscription_response(user_dict, encoded, plain_text=None):
    body = encoded if plain_text is None else plain_text
    resp = Response(body, content_type="text/plain; charset=utf-8")
    resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
    resp.headers["Profile-Title"] = "base64:" + base64.b64encode(
        "⚡ Vega".encode("utf-8")
    ).decode()
    resp.headers["Profile-Update-Interval"] = "12"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Expose-Headers"] = "Subscription-Userinfo, Profile-Title"
    return resp


def _v2rayng_response(user_dict, encoded):
    """پاسخ مینیمال Base64 مخصوص v2rayNG اندروید.

    فقط چیزی که لازم است فرستاده می‌شود: بدنهٔ Base64 یک‌خطی (standard alphabet،
    بدون BOM، بدون خط خالی انتهایی) + هدر مصرف. هدرهای تزئینی مثل Profile-Title
    حذف شده‌اند تا هیچ پارسر سخت‌گیری گیر نکند.
    """
    resp = Response(encoded.strip(), content_type="text/plain; charset=utf-8")
    resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
    resp.headers["Profile-Update-Interval"] = "12"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/sub/<user_uuid>/v2rayng")
@app.route("/sub64/<user_uuid>")
def subscription_v2rayng(user_uuid):
    """لینک اشتراک اختصاصی v2rayNG (Base64 خالص).

    پیش‌فرض: نام کانفیگ‌ها ASCII است (VEGA | 1 | user) و بدنه فقط Base64.
    `?full=1` نام‌های یونیکد/ایموجی پنل را برمی‌گرداند.
    `?plain=1` همان ۸ خط را بدون Base64 می‌دهد (برای دیباگ).
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    user = c.fetchone()
    conn.close()

    if not user:
        return ("User not found", 404)

    user_dict = dict(user)
    ascii_names = str(request.args.get("full", "")).lower() not in ("1", "true", "yes", "on")
    wants_plain = str(request.args.get("plain", "")).lower() in ("1", "true", "yes", "on", "text")

    host, port, tls = resolve_public_endpoint()
    _, encoded = _build_subscription_payload(
        user_dict, host, port, tls, ascii_names=ascii_names
    )

    if wants_plain:
        return _raw_subscription_response(user_dict, encoded, user_dict.get("_raw_text", ""))

    return _v2rayng_response(user_dict, encoded)


@app.route("/sub/<user_uuid>/raw")
def subscription_raw(user_uuid):
    """همیشه خروجی خام base64 (برای کلاینت‌ها و تست دستی)"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    user = c.fetchone()
    conn.close()

    if not user:
        return ("User not found", 404)

    user_dict = dict(user)
    host, port, tls = resolve_public_endpoint()
    _, encoded = _build_subscription_payload(user_dict, host, port, tls)
    return _raw_subscription_response(user_dict, encoded)


@app.route("/sub/<user_uuid>")
def subscription(user_uuid):
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    user = c.fetchone()

    conn.close()

    if not user:
        return ("User not found", 404)

    user_dict = dict(user)
    ua = request.headers.get("User-Agent", "")

    wants_raw = str(request.args.get("raw", "")).lower() in ("1", "true", "yes", "on", "b64", "base64")
    wants_page = str(request.args.get("view", "")).lower() in ("1", "true", "yes", "on", "page")
    wants_plain = str(request.args.get("plain", "")).lower() in ("1", "true", "yes", "on", "text")

    host, port, tls = resolve_public_endpoint()
    all_configs, encoded = _build_subscription_payload(user_dict, host, port, tls)

    # کلاینت‌ها (v2rayNG، Clash، Hiddify، ...) همیشه خروجی خام می‌گیرند
    if wants_plain:
        # خروجی متنی (بدون Base64) — برای دیباگ و کلاینت‌هایی که Base64 دوست ندارند
        return _raw_subscription_response(
            user_dict, encoded, user_dict.get("_raw_text", "")
        )

    if wants_raw or (not wants_page and _is_client_ua(ua)):
        return _raw_subscription_response(user_dict, encoded)

    # ---------- صفحهٔ وب (مرورگر) ----------
    created_dt = datetime.fromisoformat(user_dict["created_at"])
    elapsed_days = (datetime.now() - created_dt).days
    days_left = max(0, user_dict["expire_days"] - elapsed_days)

    used_gb = round(user_dict["used_bytes"] / (1024 ** 3), 2)
    remaining_gb = max(0.0, round(user_dict["quota_gb"] - used_gb, 2))

    percent = (
        used_gb / user_dict["quota_gb"] * 100
        if user_dict["quota_gb"] > 0 else 0
    )

    resp = Response(render_template(
        "subscription.html",
        user_name=user_dict["name"],
        used_gb=used_gb,
        quota_gb=user_dict["quota_gb"],
        remaining_gb=remaining_gb,
        days_left=days_left,
        percent=round(percent, 1),
        configs=all_configs,
        sub_raw=encoded,
        sub_url=build_sub_url(user_uuid),
        sub_v2rayng_url=build_sub_url(user_uuid) + "/v2rayng",
        sub_page_url=request.url.split("?")[0] + "?view=1",
        public_port=port,
        public_tls=tls,
    ))
    resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def run_telegram_bot_thread():
    if not telebot:
        print("[Telegram Bot] telebot module not found. Skipping bot launch.")
        return

    while True:
        try:
            tg_token = get_setting("telegram_token", "").strip()
            tg_admin_id = get_setting("telegram_admin_id", "").strip()

            if not tg_token:
                time.sleep(10)
                continue

            bot = telebot.TeleBot(tg_token)

            @bot.message_handler(commands=['start'])
            def cmd_start(message):
                chat_id = str(message.chat.id)
                if chat_id == tg_admin_id:
                    markup = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
                    btn_status = telebot.types.KeyboardButton('📊 وضعیت پنل')
                    btn_users = telebot.types.KeyboardButton('👥 لیست کاربران')
                    markup.add(btn_status, btn_users)
                    
                    bot.send_message(
                        message.chat.id,
                        "⚡ **سلام ادمین گرامی!**\nبه پنل مدیریت تلگرامی Vega خوش آمدید.\nیکی از دکمه‌های زیر را انتخاب کنید:",
                        reply_markup=markup,
                        parse_mode="Markdown"
                    )
                else:
                    bot.send_message(
                        message.chat.id,
                        "👋 **سلام کاربر عزیز!**\nبرای استعلام مشخصات کانکشن خود، لطفاً **نام کاربری** یا **UUID** خود را ارسال کنید:"
                    )

            @bot.message_handler(func=lambda m: True)
            def handle_messages(message):
                text = message.text.strip()
                chat_id = str(message.chat.id)

                if chat_id == tg_admin_id:
                    if text == '📊 وضعیت پنل':
                        users = get_all_users()
                        total = len(users)
                        active = sum(1 for u in users if is_user_active(u)[0])
                        total_bytes = sum(u["used_bytes"] for u in users)
                        total_gb = round(total_bytes / (1024 ** 3), 2)

                        msg = (
                            f"🌐 **وضعیت سرور Vega**\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"👥 کل کاربران: {total} کاربر\n"
                            f"🟢 کاربران فعال: {active} کاربر\n"
                            f"📊 مصرف کل دیتابیس: {total_gb} GB\n"
                            f"━━━━━━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                    elif text == '👥 لیست کاربران':
                        users = get_all_users()
                        if not users:
                            bot.send_message(chat_id, "هیچ کاربری یافت نشد.")
                            return

                        msg = "👥 **لیست کاربران پنل (نمایش ۱۵ کاربر آخر):**\n\n"
                        for u in users[:15]:
                            active, _ = is_user_active(u)
                            status = "🟢" if active else "🔴"
                            used = round(u["used_bytes"] / (1024 ** 3), 2)
                            msg += f"{status} `{u['name']}` | {used}/{u['quota_gb']} GB\n"

                        if len(users) > 15:
                            msg += f"\nو {len(users) - 15} کاربر دیگر..."

                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                else:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT * FROM users WHERE name = ? OR uuid = ?", (text, text))
                    user = c.fetchone()
                    conn.close()

                    if user:
                        u = dict(user)
                        used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
                        
                        active, reason = is_user_active(u)
                        if active:
                            status = "فعال 🟢"
                        else:
                            if reason == "limit_exceeded":
                                status = "اتمام حجم 🔴"
                            elif reason == "expired":
                                status = "پایان اعتبار زمانی 🔴"
                            else:
                                status = "غیرفعال 🔴"
                        
                        try:
                            created_dt = datetime.fromisoformat(u["created_at"])
                            elapsed_days = (datetime.now() - created_dt).days
                            days_left = max(0, u["expire_days"] - elapsed_days)
                        except Exception:
                            days_left = u["expire_days"]

                        msg = (
                            f"👤 **مشخصات اشتراک شما**\n"
                            f"━━━━━━━━━━━━━\n"
                            f"🆔 نام کاربری: `{u['name']}`\n"
                            f"⚡ وضعیت اکانت: {status}\n"
                            f"📊 ترافیک مصرفی: {used_gb} GB\n"
                            f"💾 سقف حجم کل: {u['quota_gb']} GB\n"
                            f"📅 اعتبار باقی‌مانده: {days_left} روز\n"
                            f"━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")
                    else:
                        bot.send_message(chat_id, "❌ کاربری با این نام یا UUID یافت نشد.")

            print("[Telegram Bot] Bot polling started successfully.")
            bot.infinity_polling(timeout=10, long_polling_timeout=5)

        except Exception as e:
            print("[Telegram Bot] Polling crash/error, restarting in 10s:", e)
            time.sleep(10)

def start_telegram_bot():
    t = threading.Thread(target=run_telegram_bot_thread, daemon=True)
    t.start()

if __name__ == "__main__":
    init_db()
    restart_xray()
    start_nginx()
    start_stats_collector()
    start_telegram_bot()
    app.run(host="127.0.0.1", port=FLASK_PORT)
