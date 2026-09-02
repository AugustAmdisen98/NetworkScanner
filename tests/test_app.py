import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch

import app as sentinel


class IpSentinelTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = sentinel.DB_PATH
        sentinel.DB_PATH = str(Path(self.temp_dir.name) / "scanner.db")
        self.detect_patch = patch.object(sentinel, "_detect_network", return_value="192.168.70.0/24")
        self.detect_patch.start()
        sentinel._setup_database()
        sentinel.app.config.update(
            TESTING=True,
            AUTH_REQUIRED=False,
            CSRF_ENABLED=False,
            SECRET_KEY="test-secret",
            APP_PASSWORD="test-password",
        )
        self.client = sentinel.app.test_client()

    def tearDown(self):
        sentinel.app.config.update(AUTH_REQUIRED=True, CSRF_ENABLED=True)
        sentinel.DB_PATH = self.original_db
        self.detect_patch.stop()
        self.temp_dir.cleanup()

    def test_scan_logs_every_ip_and_creates_alarm(self):
        found = [
            ("192.168.70.1", "aa:bb:cc:dd:ee:01"),
            ("192.168.70.20", "aa:bb:cc:dd:ee:20"),
        ]
        with patch.object(sentinel, "scan_network", return_value=found):
            response = self.client.post("/scan")

        self.assertEqual(response.status_code, 302)
        with sentinel._connect() as db:
            log = db.execute("SELECT * FROM scan_log").fetchone()
            history_count = db.execute("SELECT COUNT(*) FROM scan_devices").fetchone()[0]
            alarm = db.execute("SELECT * FROM alarms").fetchone()
        self.assertEqual(log["active_count"], 2)
        self.assertEqual(log["unknown_count"], 2)
        self.assertEqual(history_count, 2)
        self.assertIn("192.168.70.20", alarm["message"])

    def test_reserved_ip_is_approved_immediately(self):
        self.client.post("/reserved", data={"ip": "192.168.70.20", "name": "Printer"})
        with patch.object(
            sentinel,
            "scan_network",
            return_value=[("192.168.70.20", "aa:bb:cc:dd:ee:20")],
        ):
            self.client.post("/scan")

        with sentinel._connect() as db:
            device = db.execute("SELECT * FROM devices").fetchone()
            alarm_count = db.execute("SELECT COUNT(*) FROM alarms").fetchone()[0]
        self.assertEqual(device["approved"], 1)
        self.assertEqual(alarm_count, 0)

    def test_registered_mac_mismatch_creates_alarm(self):
        self.client.post(
            "/reserved",
            data={
                "ip": "192.168.70.20",
                "name": "Printer",
                "expected_mac": "aa:bb:cc:dd:ee:20",
            },
        )
        with patch.object(
            sentinel,
            "scan_network",
            return_value=[("192.168.70.20", "aa:bb:cc:dd:ee:99")],
        ):
            self.client.post("/scan")

        with sentinel._connect() as db:
            device = db.execute("SELECT status FROM devices").fetchone()
            alarm = db.execute("SELECT message FROM alarms").fetchone()
        self.assertEqual(device["status"], "mac_mismatch")
        self.assertIn("MAC-afvigelse", alarm["message"])

    def test_invalid_ip_and_sql_injection_are_rejected(self):
        self.client.post(
            "/reserved",
            data={"ip": "192.168.70.20' OR 1=1 --", "name": "Forsøg"},
        )
        with sentinel._connect() as db:
            count = db.execute("SELECT COUNT(*) FROM reserved").fetchone()[0]
        self.assertEqual(count, 0)

    def test_jinja_escapes_message(self):
        response = self.client.get("/?message=<script>alert(1)</script>")
        self.assertNotIn(b"<script>alert(1)</script>", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_login_and_csrf_are_required(self):
        sentinel.app.config.update(AUTH_REQUIRED=True, CSRF_ENABLED=True)
        client = sentinel.app.test_client()

        response = client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

        client.get("/login")
        with client.session_transaction() as flask_session:
            token = flask_session["csrf_token"]
        response = client.post(
            "/login",
            data={"password": "test-password", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        response = client.post("/settings", data={"network": "192.168.70.0/24", "interval": "0"})
        self.assertEqual(response.status_code, 400)

    def test_schedule_change_wakes_scheduler(self):
        sentinel.SCHEDULER_WAKE.clear()
        self.client.post(
            "/settings",
            data={"network": "192.168.70.0/24", "interval": "5"},
        )
        self.assertTrue(sentinel.SCHEDULER_WAKE.is_set())
        self.assertEqual(sentinel._get_setting("interval", "0"), "5")

    def test_email_alarm_uses_smtp_when_configured(self):
        environment = {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_FROM": "sentinel@example.com",
            "ALERT_EMAIL": "admin@example.com",
            "SMTP_TLS": "1",
        }
        with patch.dict(os.environ, environment, clear=False), patch.object(sentinel.smtplib, "SMTP") as smtp:
            result = sentinel._send_email_alarm("Testalarm")

        smtp.assert_called_once_with("smtp.example.com", 587, timeout=15)
        smtp.return_value.__enter__.return_value.starttls.assert_called_once()
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()
        self.assertIn("admin@example.com", result)

    def test_scan_rejects_overly_large_network(self):
        with self.assertRaises(ValueError):
            sentinel.scan_network("10.0.0.0/8")


if __name__ == "__main__":
    unittest.main()
