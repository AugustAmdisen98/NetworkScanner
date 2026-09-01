# IP Sentinel

En simpel Flask- og Scapy-app til de fire krav i opgaven:

1. Scan et IPv4-netværk for aktive IP-adresser.
2. Planlæg scanninger og log resultaterne.
3. Sammenlign scannede IP-adresser med reserverede IP-adresser i SQLite.
4. Vis og log alarm, når en aktiv IP-adresse ikke findes i databasen.

## Kør lokalt

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python app.py
```

Åbn derefter `http://127.0.0.1:5000`.

Scapy-scanning kræver typisk administrator/root-rettigheder og fungerer bedst på samme lokale netværk som de enheder, der skal findes.

## Raspberry Pi

Når appen starter, udfylder den automatisk netværket ud fra Pi'ens aktive ethernet- eller wifi-forbindelse. Hvis Pi'en senere flyttes til et andet netværk, skal appen bare startes igen, eller siden skal genindlæses mens "Find netværk automatisk" er slået til.

```bash
git pull
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python app.py
```
