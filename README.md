# IP Sentinel

IP Sentinel er en Flask-, SQLite- og Scapy-applikation til overvågning af aktive IPv4-adresser.

## Funktioner

- finder automatisk det lokale netværk på Raspberry Pi/Linux
- scanner aktive IP- og MAC-adresser med Scapy ARP
- administrerer reserverede IP-adresser i webinterfacet
- registrerer valgfri forventet MAC-adresse og alarmerer ved afvigelser
- sammenligner aktive IP'er med databasen
- kører manuelle eller planlagte scanninger
- gemmer hver scanning og hver fundet IP/MAC permanent
- viser og gemmer alarmer ved ukendte IP-adresser
- sender valgfri e-mailalarm via SMTP
- beskytter webappen med login, CSRF-token, inputvalidering og sikkerhedsheaders
- bruger parameteriseret SQL og Jinja-escaping mod SQL-injection og XSS

## Lokal installation på Windows

Installer Python, Npcap og projektets pakker. Kør PowerShell som administrator:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:APP_PASSWORD = "vælg-en-god-adgangskode"
$env:SECRET_KEY = "en-lang-tilfældig-værdi"
.venv\Scripts\python app.py
```

Åbn `http://127.0.0.1:5000`.

## Raspberry Pi 3

```bash
git pull
sudo apt update
sudo apt install -y python3-venv python3-full libpcap-dev
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export APP_PASSWORD='vælg-en-god-adgangskode'
export SECRET_KEY='en-lang-tilfældig-værdi'
sudo --preserve-env=APP_PASSWORD,SECRET_KEY .venv/bin/python app.py
```

Find Pi'ens adresse med `hostname -I`, og åbn derefter `http://PI-ADRESSE:5000` fra en computer på samme netværk. Appen lytter på alle lokale interfaces, men kræver login. Stop den med `Ctrl+C`.

## E-mailalarm

E-mail er valgfri. Uden SMTP gemmes alarmen stadig i databasen og vises i webinterface og terminal.

```text
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_FROM=ip-sentinel@example.com
ALERT_EMAIL=modtager@example.com
SMTP_USERNAME=brugernavn
SMTP_PASSWORD=adgangskode
SMTP_TLS=1
SMTP_SSL=0
```

På Raspberry Pi skal de relevante variabler også medtages i `sudo --preserve-env=...`, hvis e-mail bruges.

## Test

Testene sender ingen netværkspakker; Scapy-resultater simuleres.

```bash
python -m unittest discover -s tests -v
```

Scan kun netværk, som du ejer eller har tilladelse til at teste.
