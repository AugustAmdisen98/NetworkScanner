import ipaddress
import os
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime

from flask import Flask, redirect, render_template_string, request, url_for


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "scanner.db")

SCAN_LOCK = threading.Lock()
SCHEDULER_STARTED = False


PAGE = """
<!doctype html>
<html lang="da">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{% if refresh_seconds %}<meta http-equiv="refresh" content="{{ refresh_seconds }}">{% endif %}
<title>IP Sentinel</title>
<style>
  :root { color-scheme: light; --line:#d7dde5; --soft:#f5f7fa; --bad:#fff0f0; --good:#eefbf1; }
  * { box-sizing: border-box; }
  body { font-family: Arial, sans-serif; max-width: 980px; margin: 32px auto; padding: 0 16px; color:#17202a; }
  h1 { margin-bottom: 4px; }
  h2 { margin-top: 28px; border-top: 1px solid var(--line); padding-top: 18px; }
  form { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; align-items: center; }
  input, button { padding: 8px 10px; border: 1px solid #b8c2cc; border-radius: 4px; font: inherit; }
  button { background: #1f6feb; color: white; border-color: #1f6feb; cursor: pointer; }
  button.secondary { background: #475569; border-color: #475569; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { padding: 9px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
  th { background: var(--soft); }
  .ok { background: var(--good); }
  .alarm { background: var(--bad); }
  .message { padding: 10px 12px; background: var(--soft); border-left: 4px solid #1f6feb; }
  .muted { color: #657282; }
</style>

<h1>IP Sentinel</h1>
<p class="muted">Scanner aktive IP-adresser, sammenligner med databasen, logger scanninger og viser alarm ved ukendte IP'er.</p>

{% if message %}<p class="message">{{ message }}</p>{% endif %}

<h2>1. Netværksscanning og planlægning</h2>
<form method="post" action="{{ url_for('save_settings') }}">
  <label>Netværk
    <input name="network" value="{{ network }}" placeholder="192.168.1.0/24" required>
  </label>
  <label>
    <input name="auto_network" type="checkbox" value="1" {{ 'checked' if auto_network else '' }}>
    Find netværk automatisk
  </label>
  <label>Interval i minutter
    <input name="interval" type="number" min="0" value="{{ interval }}" required>
  </label>
  <button>Gem plan</button>
</form>
<form method="post" action="{{ url_for('scan_now') }}">
  <input type="hidden" name="network" value="{{ network }}">
  <button class="secondary">Scan nu</button>
</form>
<p class="muted">Automatisk netværk bruger den aktive ethernet/wifi-forbindelse. Sæt interval til 0 for kun at scanne manuelt.</p>
<p><strong>Scheduler:</strong> {{ scheduler_status }}</p>
{% if next_scan_at %}<p class="muted">Næste planlagte scanning: {{ next_scan_at }}</p>{% endif %}

<h2>2. Reserverede IP-adresser</h2>
<form method="post" action="{{ url_for('add_reserved') }}">
  <input name="ip" placeholder="192.168.1.10" required>
  <input name="name" placeholder="Navn eller udstyr" required>
  <button>Gem</button>
</form>
<table>
  <tr><th>IP</th><th>Navn</th><th></th></tr>
  {% for item in reserved %}
  <tr>
    <td>{{ item["ip"] }}</td>
    <td>{{ item["name"] }}</td>
    <td>
      <form method="post" action="{{ url_for('delete_reserved') }}">
        <input type="hidden" name="ip" value="{{ item['ip'] }}">
        <button class="secondary">Slet</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3" class="muted">Ingen reserverede IP-adresser endnu.</td></tr>
  {% endfor %}
</table>

<h2>3. Seneste scanning</h2>
<table>
  <tr><th>IP</th><th>MAC</th><th>Status</th><th>Sidst set</th></tr>
  {% for device in devices %}
  <tr class="{{ 'ok' if device['approved'] else 'alarm' }}">
    <td>{{ device["ip"] }}</td>
    <td>{{ device["mac"] }}</td>
    <td>{{ 'Godkendt' if device['approved'] else 'ALARM: Ukendt IP' }}</td>
    <td>{{ device["last_seen"] }}</td>
  </tr>
  {% else %}
  <tr><td colspan="4" class="muted">Ingen scanninger logget endnu.</td></tr>
  {% endfor %}
</table>

<h2>4. Log og alarmer</h2>
<table>
  <tr><th>Tidspunkt</th><th>Netværk</th><th>Aktive IP'er</th><th>Ukendte</th><th>Alarm</th></tr>
  {% for row in logs %}
  <tr class="{{ 'alarm' if row['unknown_count'] else '' }}">
    <td>{{ row["scanned_at"] }}</td>
    <td>{{ row["network"] }}</td>
    <td>{{ row["active_count"] }}</td>
    <td>{{ row["unknown_count"] }}</td>
    <td>{{ row["alarm"] or '-' }}</td>
  </tr>
  {% else %}
  <tr><td colspan="5" class="muted">Loggen er tom.</td></tr>
  {% endfor %}
</table>
</html>
"""


def scan_network(network):
    """Funktion 1: Scan et IPv4-netværk for aktive IP- og MAC-adresser."""
    target = ipaddress.ip_network(network, strict=False)
    if target.version != 4 or target.prefixlen < 24:
        raise ValueError("Brug et IPv4-netværk på /24 eller mindre, fx 192.168.1.0/24")

    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target))
    answers = srp(packet, timeout=2, verbose=False)[0]
    return sorted({answer.psrc: answer.hwsrc for _, answer in answers}.items())


def log_scan(network, devices, unknown_devices, alarm_message):
    """Funktion 2: Log hver scanning og gem den seneste netværkstilstand."""
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as db:
        db.execute("DELETE FROM devices")
        db.executemany(
            "INSERT INTO devices (ip, mac, last_seen, approved) VALUES (?, ?, ?, ?)",
            [(device["ip"], device["mac"], scanned_at, int(device["approved"])) for device in devices],
        )
        db.execute(
            """
            INSERT INTO scan_log (network, scanned_at, active_count, unknown_count, alarm)
            VALUES (?, ?, ?, ?, ?)
            """,
            (network, scanned_at, len(devices), len(unknown_devices), alarm_message),
        )
    return scanned_at


def compare_with_database(scanned_devices):
    """Funktion 3: Sammenlign scannede IP'er med reserverede IP'er i databasen."""
    with _connect() as db:
        reserved_ips = {row["ip"] for row in db.execute("SELECT ip FROM reserved")}

    devices = []
    unknown_devices = []
    for ip, mac in scanned_devices:
        device = {"ip": ip, "mac": mac, "approved": ip in reserved_ips}
        devices.append(device)
        if not device["approved"]:
            unknown_devices.append(device)
    return devices, unknown_devices


def send_alarm(unknown_devices):
    """Funktion 4: Udsend en simpel alarm, når aktive IP'er ikke er reserveret."""
    if not unknown_devices:
        return ""

    ips = ", ".join(device["ip"] for device in unknown_devices)
    message = f"Ukendte aktive IP-adresser: {ips}"
    print(f"ALARM: {message}", flush=True)
    with _connect() as db:
        db.execute(
            "INSERT INTO alarms (created_at, message) VALUES (?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message),
        )
    return message


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _setup_database():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS reserved (ip TEXT PRIMARY KEY, name TEXT NOT NULL)")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                approved INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                active_count INTEGER NOT NULL,
                unknown_count INTEGER NOT NULL,
                alarm TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS alarms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        db.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO settings (name, value) VALUES ('network_mode', 'auto')")
        db.execute("INSERT OR IGNORE INTO settings (name, value) VALUES ('network', ?)", (_detect_network(),))
        db.execute("INSERT OR IGNORE INTO settings (name, value) VALUES ('interval', '0')")
        db.execute("INSERT OR IGNORE INTO settings (name, value) VALUES ('scheduler_status', 'Planlagt scanning er slået fra.')")
        db.execute("INSERT OR IGNORE INTO settings (name, value) VALUES ('next_scan_at', '')")


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
            "INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
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
        scanned_at = log_scan(network, devices, unknown, alarm)
    return f"Scanning færdig {scanned_at}. Fandt {len(devices)} aktive IP'er og {len(unknown)} ukendte."


def _scheduler_loop():
    next_scan = 0.0
    while True:
        try:
            interval = int(_get_setting("interval", "0"))
            if interval > 0 and time.monotonic() >= next_scan:
                started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                _set_scheduler_status(f"Scanner automatisk nu ({started_at}).")
                _run_scan(_get_network())
                next_scan = time.monotonic() + interval * 60
                _set_scheduler_status("Planlagt scanning kører.", _time_text(time.time() + interval * 60))
            elif interval <= 0:
                next_scan = 0.0
                _set_scheduler_status("Planlagt scanning er slået fra.")
            elif next_scan > 0:
                _set_scheduler_status("Planlagt scanning kører.", _time_text(time.time() + max(0, next_scan - time.monotonic())))
        except Exception as error:
            message = f"Planlagt scanning fejlede: {error}"
            print(message, flush=True)
            next_scan = time.monotonic() + 60
            _set_scheduler_status(message, _time_text(time.time() + 60))
        time.sleep(5)


def _start_scheduler():
    global SCHEDULER_STARTED
    if SCHEDULER_STARTED:
        return
    SCHEDULER_STARTED = True
    threading.Thread(target=_scheduler_loop, daemon=True).start()


@app.get("/")
def index():
    auto_network = _get_setting("network_mode", "auto") == "auto"
    network = _get_network()
    interval = _get_setting("interval", "0")
    refresh_seconds = 30 if int(interval) > 0 else 0
    message = request.args.get("message", "")
    with _connect() as db:
        reserved = db.execute("SELECT ip, name FROM reserved ORDER BY ip").fetchall()
        devices = db.execute("SELECT ip, mac, last_seen, approved FROM devices ORDER BY ip").fetchall()
        logs = db.execute(
            "SELECT network, scanned_at, active_count, unknown_count, alarm FROM scan_log ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return render_template_string(
        PAGE,
        reserved=reserved,
        devices=devices,
        logs=logs,
        network=network,
        auto_network=auto_network,
        interval=interval,
        refresh_seconds=refresh_seconds,
        scheduler_status=_get_setting("scheduler_status", "Planlagt scanning er slået fra."),
        next_scan_at=_get_setting("next_scan_at", ""),
        message=message,
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
        interval = max(0, int(request.form["interval"]))
        _set_setting("network", network)
        _set_setting("interval", str(interval))
        if interval > 0:
            _set_scheduler_status("Planen er gemt. Første automatiske scanning starter inden for få sekunder.")
        else:
            _set_scheduler_status("Planlagt scanning er slået fra.")
        message = "Planen er gemt."
    except ValueError as error:
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
        if not name:
            raise ValueError("Navn mangler")
        with _connect() as db:
            db.execute(
                "INSERT INTO reserved (ip, name) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET name = excluded.name",
                (ip, name),
            )
        message = f"{ip} er gemt."
    except ValueError as error:
        message = f"Fejl: {error}"
    return redirect(url_for("index", message=message))


@app.post("/reserved/delete")
def delete_reserved():
    with _connect() as db:
        db.execute("DELETE FROM reserved WHERE ip = ?", (request.form["ip"],))
    return redirect(url_for("index", message="IP-adressen er slettet."))


_setup_database()
_start_scheduler()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
