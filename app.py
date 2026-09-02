import ipaddress
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import subprocess
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from email.message import EmailMessage

from flask import Flask, abort, redirect, render_template_string, request, session, url_for


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-development-key"),
    APP_PASSWORD=os.environ.get("APP_PASSWORD", "admin"),
    AUTH_REQUIRED=os.environ.get("AUTH_REQUIRED", "1") != "0",
    CSRF_ENABLED=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "0") == "1",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "scanner.db")

SCAN_LOCK = threading.Lock()
SCHEDULER_WAKE = threading.Event()
SCHEDULER_STARTED = False
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


LOGIN_PAGE = """
<!doctype html>
<html lang="da">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log ind - IP Sentinel</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 420px; margin: 12vh auto; padding: 0 16px; color:#17202a; }
  form { display:grid; gap:10px; border:1px solid #d7dde5; padding:22px; border-radius:8px; }
  input,button { padding:10px; font:inherit; }
  button { background:#1f6feb; color:white; border:0; border-radius:4px; cursor:pointer; }
  .error { background:#fff0f0; padding:10px; }
</style>
<h1>IP Sentinel</h1>
{% if message %}<p class="error">{{ message }}</p>{% endif %}
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Adgangskode</label>
  <input type="password" name="password" required autofocus>
  <button>Log ind</button>
</form>
</html>
"""


PAGE = """
<!doctype html>
<html lang="da">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Sentinel</title>
<style>
  :root { color-scheme:light; --line:#d7dde5; --soft:#f5f7fa; --bad:#fff0f0; --good:#eefbf1; }
  * { box-sizing:border-box; }
  body { font-family:Arial,sans-serif; max-width:1050px; margin:32px auto; padding:0 16px; color:#17202a; }
  header { display:flex; justify-content:space-between; gap:20px; align-items:start; }
  h1 { margin-bottom:4px; }
  h2 { margin-top:28px; border-top:1px solid var(--line); padding-top:18px; }
  form { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0; align-items:center; }
  input,button { padding:8px 10px; border:1px solid #b8c2cc; border-radius:4px; font:inherit; }
  button { background:#1f6feb; color:white; border-color:#1f6feb; cursor:pointer; }
  button.secondary { background:#475569; border-color:#475569; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th,td { padding:9px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
  th { background:var(--soft); }
  .ok { background:var(--good); }
  .alarm { background:var(--bad); }
  .message { padding:10px 12px; background:var(--soft); border-left:4px solid #1f6feb; }
  .warning { padding:10px 12px; background:#fff8db; border-left:4px solid #d89b00; }
  .muted { color:#657282; }
  .pill { display:inline-block; padding:3px 8px; border-radius:999px; background:var(--soft); border:1px solid var(--line); }
  .table-wrap { overflow-x:auto; }
</style>

<header>
  <div>
    <h1>IP Sentinel</h1>
    <p class="muted">Scanner aktive IP-adresser, sammenligner med databasen, logger scanninger og udsender alarm.</p>
  </div>
  {% if auth_required %}
  <form method="post" action="{{ url_for('logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button class="secondary">Log ud</button>
  </form>
  {% endif %}
</header>

{% if default_credentials %}<p class="warning">Standardadgangskoden er stadig <strong>admin</strong>. Sæt APP_PASSWORD og SECRET_KEY før demonstration på netværket.</p>{% endif %}
{% if message %}<p class="message">{{ message }}</p>{% endif %}

<h2>1. Netværksscanning og planlægning</h2>
<form method="post" action="{{ url_for('save_settings') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <label>Netværk
    <input name="network" value="{{ network }}" placeholder="192.168.1.0/24" required>
  </label>
  <label>
    <input name="auto_network" type="checkbox" value="1" {{ 'checked' if auto_network else '' }}>
    Find netværk automatisk
  </label>
  <label>Interval i minutter
    <input name="interval" type="number" min="0" max="10080" value="{{ interval }}" required>
  </label>
  <button>Gem plan</button>
</form>
<form method="post" action="{{ url_for('scan_now') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button class="secondary">Scan nu</button>
</form>
<p class="muted">Automatisk netværk bruger den aktive ethernet/wifi-forbindelse. Sæt interval til 0 for kun at scanne manuelt.</p>
<p><strong>Scheduler:</strong> {{ scheduler_status }}</p>
{% if next_scan_at %}<p class="muted">Næste planlagte scanning: {{ next_scan_at }}</p>{% endif %}
{% if refresh_seconds %}<p class="muted">Siden opdaterer automatisk hvert <span class="pill">{{ refresh_seconds }}</span> sekund.</p>{% endif %}

<h2>2. Reserverede IP-adresser</h2>
<form method="post" action="{{ url_for('add_reserved') }}">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="ip" placeholder="192.168.1.10" required>
  <input name="name" placeholder="Navn eller udstyr" maxlength="80" required>
  <input name="expected_mac" placeholder="Forventet MAC (valgfri)" maxlength="17">
  <button>Gem</button>
</form>
<div class="table-wrap"><table>
  <tr><th>IP</th><th>Navn</th><th>Forventet MAC</th><th></th></tr>
  {% for item in reserved %}
  <tr>
    <td>{{ item["ip"] }}</td><td>{{ item["name"] }}</td><td>{{ item["expected_mac"] or '-' }}</td>
    <td><form method="post" action="{{ url_for('delete_reserved') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="ip" value="{{ item['ip'] }}">
      <button class="secondary">Slet</button>
    </form></td>
  </tr>
  {% else %}<tr><td colspan="4" class="muted">Ingen reserverede IP-adresser endnu.</td></tr>{% endfor %}
</table></div>

<h2>3. Seneste scanning</h2>
<div class="table-wrap"><table>
  <tr><th>IP</th><th>MAC</th><th>Status</th><th>Sidst set</th></tr>
  {% for device in devices %}
  <tr class="{{ 'ok' if device['approved'] else 'alarm' }}">
    <td>{{ device["ip"] }}</td><td>{{ device["mac"] }}</td>
    <td>{{ 'Godkendt' if device['status'] == 'approved' else 'ALARM: MAC afviger' if device['status'] == 'mac_mismatch' else 'ALARM: Ukendt IP' }}</td><td>{{ device["last_seen"] }}</td>
  </tr>
  {% else %}<tr><td colspan="4" class="muted">Ingen scanninger logget endnu.</td></tr>{% endfor %}
</table></div>

<h2>4. Scanningslog</h2>
<div class="table-wrap"><table>
  <tr><th>Tidspunkt</th><th>Netværk</th><th>Aktive IP'er</th><th>Ukendte</th><th>Alarm</th></tr>
  {% for row in logs %}
  <tr class="{{ 'alarm' if row['unknown_count'] else '' }}">
    <td>{{ row["scanned_at"] }}</td><td>{{ row["network"] }}</td><td>{{ row["active_count"] }}</td>
    <td>{{ row["unknown_count"] }}</td><td>{{ row["alarm"] or '-' }}</td>
  </tr>
  {% else %}<tr><td colspan="5" class="muted">Loggen er tom.</td></tr>{% endfor %}
</table></div>

<h2>5. Historik for fundne IP-adresser</h2>
<div class="table-wrap"><table>
  <tr><th>Scanning</th><th>Tidspunkt</th><th>IP</th><th>MAC</th><th>Status</th></tr>
  {% for row in history %}
  <tr class="{{ 'ok' if row['approved'] else 'alarm' }}">
    <td>#{{ row["scan_id"] }}</td><td>{{ row["scanned_at"] }}</td><td>{{ row["ip"] }}</td>
    <td>{{ row["mac"] }}</td><td>{{ 'Godkendt' if row['status'] == 'approved' else 'MAC afviger' if row['status'] == 'mac_mismatch' else 'Ukendt IP' }}</td>
  </tr>
  {% else %}<tr><td colspan="5" class="muted">Ingen IP-historik endnu.</td></tr>{% endfor %}
</table></div>

<h2>6. Udsendte alarmer</h2>
<div class="table-wrap"><table>
  <tr><th>Tidspunkt</th><th>Besked</th><th>Levering</th></tr>
  {% for row in alarms %}
  <tr class="alarm"><td>{{ row["created_at"] }}</td><td>{{ row["message"] }}</td><td>{{ row["delivery"] }}</td></tr>
  {% else %}<tr><td colspan="3" class="muted">Ingen alarmer endnu.</td></tr>{% endfor %}
</table></div>

{% if refresh_seconds %}
<script>setTimeout(function(){ window.location.reload(); }, {{ refresh_seconds * 1000 }});</script>
{% endif %}
</html>
"""


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_request():
    public_endpoints = {"login", "health", "static"}
    if app.config["AUTH_REQUIRED"] and request.endpoint not in public_endpoints and not session.get("authenticated"):
        return redirect(url_for("login"))

    if request.method == "POST" and app.config["CSRF_ENABLED"]:
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            abort(400, "Ugyldig CSRF-token")
    return None


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def scan_network(network):
    """Scan et IPv4-netværk for aktive IP- og MAC-adresser."""
    target = ipaddress.ip_network(network, strict=False)
    if target.version != 4 or target.prefixlen < 24:
        raise ValueError("Brug et IPv4-netværk på /24 eller mindre, fx 192.168.1.0/24")

    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target))
    answers = srp(packet, timeout=3, retry=1, verbose=False)[0]
    return sorted({answer.psrc: answer.hwsrc.lower() for _, answer in answers}.items())


def compare_with_database(scanned_devices):
    """Sammenlign scannede IP'er med de reserverede IP'er."""
    with _connect() as db:
        reservations = {
            row["ip"]: row["expected_mac"].lower()
            for row in db.execute("SELECT ip, expected_mac FROM reserved")
        }

    devices = []
    unknown_devices = []
    for ip, mac in scanned_devices:
        expected_mac = reservations.get(ip)
        if expected_mac is None:
            status = "unknown_ip"
        elif expected_mac and expected_mac != mac.lower():
            status = "mac_mismatch"
        else:
            status = "approved"
        device = {
            "ip": ip,
            "mac": mac,
            "expected_mac": expected_mac or "",
            "status": status,
            "approved": status == "approved",
        }
        devices.append(device)
        if not device["approved"]:
            unknown_devices.append(device)
    return devices, unknown_devices


def log_scan(network, devices, unknown_devices, alarm_message):
    """Gem både scanningsoversigt, seneste tilstand og hver fundet IP permanent."""
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as db:
        cursor = db.execute(
            """INSERT INTO scan_log (network, scanned_at, active_count, unknown_count, alarm)
               VALUES (?, ?, ?, ?, ?)""",
            (network, scanned_at, len(devices), len(unknown_devices), alarm_message),
        )
        scan_id = cursor.lastrowid
        db.execute("DELETE FROM devices")
        db.executemany(
            "INSERT INTO devices (ip, mac, last_seen, approved, status) VALUES (?, ?, ?, ?, ?)",
            [(d["ip"], d["mac"], scanned_at, int(d["approved"]), d["status"]) for d in devices],
        )
        db.executemany(
            "INSERT INTO scan_devices (scan_id, ip, mac, approved, status) VALUES (?, ?, ?, ?, ?)",
            [(scan_id, d["ip"], d["mac"], int(d["approved"]), d["status"]) for d in devices],
        )
    return scanned_at, scan_id


def _send_email_alarm(message):
    host = os.environ.get("SMTP_HOST")
    recipient = os.environ.get("ALERT_EMAIL")
    sender = os.environ.get("SMTP_FROM")
    if not host or not recipient or not sender:
        return "Web og terminal (e-mail ikke konfigureret)"

    mail = EmailMessage()
    mail["Subject"] = "IP Sentinel: ukendt enhed fundet"
    mail["From"] = sender
    mail["To"] = recipient
    mail.set_content(message)

    port = int(os.environ.get("SMTP_PORT", "587"))
    use_ssl = os.environ.get("SMTP_SSL", "0") == "1"
    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with smtp_class(host, port, timeout=15) as smtp:
        if not use_ssl and os.environ.get("SMTP_TLS", "1") == "1":
            smtp.starttls()
        username = os.environ.get("SMTP_USERNAME")
        password = os.environ.get("SMTP_PASSWORD")
        if username and password:
            smtp.login(username, password)
        smtp.send_message(mail)
    return f"E-mail sendt til {recipient}"


def send_alarm(unknown_devices):
    """Log alarmen og send valgfri e-mail, når en aktiv IP ikke er reserveret."""
    if not unknown_devices:
        return ""

    details = []
    for device in unknown_devices:
        if device["status"] == "mac_mismatch":
            details.append(
                f"MAC-afvigelse på {device['ip']}: forventet {device['expected_mac']}, fandt {device['mac']}"
            )
        else:
            details.append(f"Ukendt IP {device['ip']} ({device['mac']})")
    message = "; ".join(details)
    print(f"ALARM: {message}", flush=True)
    try:
        delivery = _send_email_alarm(message)
    except Exception as error:
        delivery = f"E-mail fejlede: {error}"
        print(delivery, flush=True)

    with _connect() as db:
        db.execute(
            "INSERT INTO alarms (created_at, message, delivery) VALUES (?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message, delivery),
        )
    return message


@contextmanager
def _connect():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _setup_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS reserved (
                   ip TEXT PRIMARY KEY, name TEXT NOT NULL, expected_mac TEXT NOT NULL DEFAULT ''
               )"""
        )
        reserved_columns = {row["name"] for row in db.execute("PRAGMA table_info(reserved)")}
        if "expected_mac" not in reserved_columns:
            db.execute("ALTER TABLE reserved ADD COLUMN expected_mac TEXT NOT NULL DEFAULT ''")
        db.execute(
            """CREATE TABLE IF NOT EXISTS devices (
                   ip TEXT PRIMARY KEY, mac TEXT NOT NULL, last_seen TEXT NOT NULL,
                   approved INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'unknown_ip'
               )"""
        )
        device_columns = {row["name"] for row in db.execute("PRAGMA table_info(devices)")}
        if "status" not in device_columns:
            db.execute("ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown_ip'")
        db.execute(
            """CREATE TABLE IF NOT EXISTS scan_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, scanned_at TEXT NOT NULL,
                   active_count INTEGER NOT NULL, unknown_count INTEGER NOT NULL, alarm TEXT
               )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS scan_devices (
                   scan_id INTEGER NOT NULL REFERENCES scan_log(id) ON DELETE CASCADE,
                   ip TEXT NOT NULL, mac TEXT NOT NULL, approved INTEGER NOT NULL,
                   status TEXT NOT NULL DEFAULT 'unknown_ip',
                   PRIMARY KEY (scan_id, ip)
               )"""
        )
        history_columns = {row["name"] for row in db.execute("PRAGMA table_info(scan_devices)")}
        if "status" not in history_columns:
            db.execute("ALTER TABLE scan_devices ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown_ip'")
        db.execute(
            """CREATE TABLE IF NOT EXISTS alarms (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                   message TEXT NOT NULL, delivery TEXT NOT NULL DEFAULT 'Web og terminal'
               )"""
        )
        alarm_columns = {row["name"] for row in db.execute("PRAGMA table_info(alarms)")}
        if "delivery" not in alarm_columns:
            db.execute("ALTER TABLE alarms ADD COLUMN delivery TEXT NOT NULL DEFAULT 'Web og terminal'")
        db.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        defaults = {
            "network_mode": "auto",
            "network": _detect_network(),
            "interval": "0",
            "scheduler_status": "Planlagt scanning er slået fra.",
            "next_scan_at": "",
        }
        db.executemany("INSERT OR IGNORE INTO settings (name, value) VALUES (?, ?)", defaults.items())


def _detect_network():
    local_ip = _detect_local_ip()
    detected = _detect_linux_network(local_ip)
    if detected:
        return detected
    return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))


def _detect_linux_network(local_ip):
    try:
        output = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in output.splitlines():
        for part in line.split():
            if part.startswith(f"{local_ip}/"):
                return str(ipaddress.ip_network(part, strict=False))
    return None


def _detect_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        pass

    try:
        from scapy.all import conf

        _, local_ip, _ = conf.route.route("0.0.0.0")
        return local_ip
    except Exception:
        return "192.168.1.1"


def _get_setting(name, default):
    with _connect() as db:
        row = db.execute("SELECT value FROM settings WHERE name = ?", (name,)).fetchone()
    return row["value"] if row else default


def _set_setting(name, value):
    with _connect() as db:
        db.execute(
            """INSERT INTO settings (name, value) VALUES (?, ?)
               ON CONFLICT(name) DO UPDATE SET value = excluded.value""",
            (name, value),
        )


def _get_network():
    if _get_setting("network_mode", "auto") == "auto":
        network = _detect_network()
        _set_setting("network", network)
        return network
    return _get_setting("network", _detect_network())


def _set_scheduler_status(status, next_scan_at=""):
    _set_setting("scheduler_status", status)
    _set_setting("next_scan_at", next_scan_at)


def _time_text(timestamp):
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _run_scan(network):
    with SCAN_LOCK:
        scanned = scan_network(network)
        devices, unknown = compare_with_database(scanned)
        alarm = send_alarm(unknown)
        scanned_at, scan_id = log_scan(network, devices, unknown, alarm)
    return f"Scanning #{scan_id} færdig {scanned_at}. Fandt {len(devices)} aktive IP'er og {len(unknown)} ukendte."


def _scheduler_loop():
    next_scan = None
    while True:
        try:
            interval = int(_get_setting("interval", "0"))
            if interval <= 0:
                next_scan = None
                _set_scheduler_status("Planlagt scanning er slået fra.")
                SCHEDULER_WAKE.wait(5)
                SCHEDULER_WAKE.clear()
                continue

            if next_scan is None:
                next_scan = time.monotonic() + 1
                _set_scheduler_status("Planlagt scanning starter inden for få sekunder.")

            wait_seconds = min(5, max(0, next_scan - time.monotonic()))
            if SCHEDULER_WAKE.wait(wait_seconds):
                SCHEDULER_WAKE.clear()
                next_scan = None
                continue

            if time.monotonic() < next_scan:
                continue

            started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_scheduler_status(f"Scanner automatisk nu ({started_at}).")
            _run_scan(_get_network())
            next_scan = time.monotonic() + interval * 60
            _set_scheduler_status("Planlagt scanning kører.", _time_text(time.time() + interval * 60))
        except Exception as error:
            message = f"Planlagt scanning fejlede: {error}"
            print(message, flush=True)
            next_scan = time.monotonic() + 60
            _set_scheduler_status(message, _time_text(time.time() + 60))


def _start_scheduler():
    global SCHEDULER_STARTED
    if SCHEDULER_STARTED:
        return
    SCHEDULER_STARTED = True
    threading.Thread(target=_scheduler_loop, daemon=True).start()


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        supplied = request.form.get("password", "")
        expected = str(app.config["APP_PASSWORD"])
        if secrets.compare_digest(supplied.encode(), expected.encode()):
            session.clear()
            session["authenticated"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))
        message = "Forkert adgangskode."
    return render_template_string(LOGIN_PAGE, message=message)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    auto_network = _get_setting("network_mode", "auto") == "auto"
    network = _get_network()
    interval = _get_setting("interval", "0")
    refresh_seconds = 10 if int(interval) > 0 else 0
    message = request.args.get("message", "")
    with _connect() as db:
        reserved = db.execute("SELECT ip, name, expected_mac FROM reserved ORDER BY ip").fetchall()
        devices = db.execute("SELECT ip, mac, last_seen, approved, status FROM devices ORDER BY ip").fetchall()
        logs = db.execute(
            "SELECT id, network, scanned_at, active_count, unknown_count, alarm FROM scan_log ORDER BY id DESC LIMIT 20"
        ).fetchall()
        history = db.execute(
            """SELECT scan_devices.scan_id, scan_log.scanned_at, scan_devices.ip, scan_devices.mac,
                      scan_devices.approved, scan_devices.status
               FROM scan_devices JOIN scan_log ON scan_log.id = scan_devices.scan_id
               ORDER BY scan_devices.scan_id DESC, scan_devices.ip LIMIT 100"""
        ).fetchall()
        alarms = db.execute(
            "SELECT created_at, message, delivery FROM alarms ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return render_template_string(
        PAGE,
        reserved=reserved,
        devices=devices,
        logs=logs,
        history=history,
        alarms=alarms,
        network=network,
        auto_network=auto_network,
        interval=interval,
        refresh_seconds=refresh_seconds,
        scheduler_status=_get_setting("scheduler_status", "Planlagt scanning er slået fra."),
        next_scan_at=_get_setting("next_scan_at", ""),
        message=message,
        auth_required=app.config["AUTH_REQUIRED"],
        default_credentials=(app.config["APP_PASSWORD"] == "admin" or app.config["SECRET_KEY"] == "change-this-development-key"),
    )


@app.post("/settings")
def save_settings():
    try:
        if request.form.get("auto_network") == "1":
            network = _detect_network()
            _set_setting("network_mode", "auto")
        else:
            target = ipaddress.ip_network(request.form["network"], strict=False)
            if target.version != 4 or target.prefixlen < 24:
                raise ValueError("Brug et IPv4-netværk på /24 eller mindre, fx 192.168.1.0/24")
            network = str(target)
            _set_setting("network_mode", "manual")
        interval = int(request.form["interval"])
        if not 0 <= interval <= 10080:
            raise ValueError("Interval skal være mellem 0 og 10080 minutter")
        _set_setting("network", network)
        _set_setting("interval", str(interval))
        SCHEDULER_WAKE.set()
        if interval > 0:
            _set_scheduler_status("Planen er gemt. Første automatiske scanning starter inden for få sekunder.")
        else:
            _set_scheduler_status("Planlagt scanning er slået fra.")
        message = "Planen er gemt."
    except (ValueError, KeyError) as error:
        message = f"Fejl: {error}"
    return redirect(url_for("index", message=message))


@app.post("/scan")
def scan_now():
    network = _get_network()
    try:
        message = _run_scan(network)
    except Exception as error:
        message = f"Fejl: {error}"
    return redirect(url_for("index", message=message))


@app.post("/reserved")
def add_reserved():
    try:
        ip = str(ipaddress.IPv4Address(request.form["ip"]))
        name = request.form["name"].strip()[:80]
        expected_mac = request.form.get("expected_mac", "").strip().lower()
        if not name:
            raise ValueError("Navn mangler")
        if expected_mac and not MAC_PATTERN.fullmatch(expected_mac):
            raise ValueError("MAC-adressen skal ligne aa:bb:cc:dd:ee:ff")
        with _connect() as db:
            db.execute(
                """INSERT INTO reserved (ip, name, expected_mac) VALUES (?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       name = excluded.name, expected_mac = excluded.expected_mac""",
                (ip, name, expected_mac),
            )
            if expected_mac:
                db.execute(
                    """UPDATE devices SET
                           approved = CASE WHEN lower(mac) = ? THEN 1 ELSE 0 END,
                           status = CASE WHEN lower(mac) = ? THEN 'approved' ELSE 'mac_mismatch' END
                       WHERE ip = ?""",
                    (expected_mac, expected_mac, ip),
                )
            else:
                db.execute("UPDATE devices SET approved = 1, status = 'approved' WHERE ip = ?", (ip,))
        message = f"{ip} er gemt."
    except (ValueError, KeyError) as error:
        message = f"Fejl: {error}"
    return redirect(url_for("index", message=message))


@app.post("/reserved/delete")
def delete_reserved():
    ip = request.form["ip"]
    with _connect() as db:
        db.execute("DELETE FROM reserved WHERE ip = ?", (ip,))
        db.execute("UPDATE devices SET approved = 0, status = 'unknown_ip' WHERE ip = ?", (ip,))
    return redirect(url_for("index", message="IP-adressen er slettet."))


_setup_database()


if __name__ == "__main__":
    _start_scheduler()
    safe_default_host = (
        "127.0.0.1"
        if app.config["APP_PASSWORD"] == "admin" or app.config["SECRET_KEY"] == "change-this-development-key"
        else "0.0.0.0"
    )
    app.run(
        host=os.environ.get("APP_HOST", safe_default_host),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
        use_reloader=False,
    )
