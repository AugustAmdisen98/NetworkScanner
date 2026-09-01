import ipaddress
import sqlite3
from datetime import datetime

from flask import Flask, redirect, render_template_string, request, url_for


app = Flask(__name__)
DB = "scanner.db"


PAGE = """
<!doctype html>
<html lang="da">
<meta charset="utf-8">
<title>IP Sentinel</title>
<style>
body{font-family:Arial;max-width:800px;margin:40px auto}form{margin:12px 0}
input,button{padding:8px}table{width:100%;border-collapse:collapse}
td,th{padding:8px;border-bottom:1px solid #ccc;text-align:left}
.alarm{background:#ffd6d6}.ok{background:#d9f5df}
</style>
<h1>IP Sentinel</h1>

<h2>Scan netværk</h2>
<form method="post" action="/scan">
  <input name="network" value="{{ network }}" required>
  <button>Scan</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}

<h2>Fundne enheder</h2>
<table>
  <tr><th>IP</th><th>MAC</th><th>Status</th><th>Sidst set</th></tr>
  {% for device in devices %}
  <tr class="{{ 'ok' if device[3] else 'alarm' }}">
    <td>{{ device[0] }}</td><td>{{ device[1] }}</td>
    <td>{{ 'Godkendt' if device[3] else 'ALARM: Ukendt IP' }}</td>
    <td>{{ device[2] }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Reserverede IP-adresser</h2>
<form method="post" action="/add">
  <input name="ip" placeholder="192.168.1.10" required>
  <input name="name" placeholder="Printer" required>
  <button>Gem</button>
</form>
<table>
  <tr><th>IP</th><th>Navn</th><th></th></tr>
  {% for item in reserved %}
  <tr><td>{{ item[1] }}</td><td>{{ item[2] }}</td>
    <td><form method="post" action="/delete/{{ item[0] }}"><button>Slet</button></form></td>
  </tr>
  {% endfor %}
</table>
</html>
"""


def setup():
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS reserved (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, name TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, mac TEXT, seen TEXT, approved INTEGER)")


@app.get("/")
def index():
    network = request.args.get("network", "192.168.1.0/24")
    message = request.args.get("message", "")
    with sqlite3.connect(DB) as db:
        reserved = db.execute("SELECT * FROM reserved ORDER BY ip").fetchall()
        devices = db.execute("SELECT * FROM devices ORDER BY ip").fetchall()
    return render_template_string(PAGE, reserved=reserved, devices=devices, network=network, message=message)


@app.post("/add")
def add():
    try:
        ip = str(ipaddress.IPv4Address(request.form["ip"]))
        name = request.form["name"].strip()
        with sqlite3.connect(DB) as db:
            db.execute("INSERT INTO reserved (ip, name) VALUES (?, ?)", (ip, name))
    except (ValueError, sqlite3.IntegrityError):
        pass
    return redirect("/")


@app.post("/delete/<int:item_id>")
def delete(item_id):
    with sqlite3.connect(DB) as db:
        db.execute("DELETE FROM reserved WHERE id = ?", (item_id,))
    return redirect("/")


@app.post("/scan")
def scan():
    network = request.form["network"]
    try:
        target = ipaddress.ip_network(network, strict=False)
        if target.version != 4 or target.prefixlen < 24:
            raise ValueError("Brug et IPv4-netværk som 192.168.1.0/24")

        from scapy.all import ARP, Ether, srp

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target))
        answers = srp(packet, timeout=2, verbose=False)[0]
        found = {(answer.psrc, answer.hwsrc) for _, answer in answers}

        with sqlite3.connect(DB) as db:
            approved = {row[0] for row in db.execute("SELECT ip FROM reserved")}
            db.execute("DELETE FROM devices")
            db.executemany(
                "INSERT INTO devices VALUES (?, ?, ?, ?)",
                [(ip, mac, datetime.now().strftime("%H:%M:%S"), ip in approved) for ip, mac in found],
            )
        message = f"Fandt {len(found)} enheder"
    except Exception as error:
        message = f"Fejl: {error}"
    return redirect(url_for("index", network=network, message=message))


setup()

if __name__ == "__main__":
    app.run(debug=True)
