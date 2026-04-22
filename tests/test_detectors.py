from __future__ import annotations

import unittest

from core.analytics import TrafficAnalytics
from core.config import ThresholdSettings
from core.log_tailer import LogRecord
from detectors.api import APIDetector
from detectors.auth import AuthDetector
from detectors.ddos import ConnectionFloodDetector
from detectors.mail import MailDetector
from detectors.web import WebDetector


class DetectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_detector_flags_ssh_bruteforce(self) -> None:
        thresholds = ThresholdSettings(ssh_failures_per_5m=2)
        detector = AuthDetector(thresholds, TrafficAnalytics())
        record = LogRecord(
            category="system",
            pattern="/var/log/secure",
            path="/var/log/secure",
            line="Apr 22 sshd[1]: Failed password for root from 198.51.100.10 port 22 ssh2",
        )
        self.assertEqual(await detector.detect(record), [])
        findings = await detector.detect(record)
        self.assertEqual(findings[0].event_type, "brute_force")
        self.assertEqual(findings[0].ip, "198.51.100.10")

    async def test_web_detector_flags_xmlrpc_attack(self) -> None:
        thresholds = ThresholdSettings(xmlrpc_posts_per_5m=2)
        detector = WebDetector(thresholds, TrafficAnalytics())
        record = LogRecord(
            category="web",
            pattern="/etc/apache2/logs/domlogs/*",
            path="/etc/apache2/logs/domlogs/example.com",
            line='198.51.100.20 - - [22/Apr/2026:10:00:00 +0000] "POST /xmlrpc.php HTTP/1.1" 200 123 "-" "bot"',
        )
        first_findings = await detector.detect(record)
        self.assertFalse(any(item.event_type == "xmlrpc_bruteforce" for item in first_findings))
        findings = await detector.detect(record)
        self.assertTrue(any(item.event_type == "xmlrpc_bruteforce" for item in findings))

    async def test_mail_detector_flags_outbound_burst(self) -> None:
        thresholds = ThresholdSettings(outbound_emails_per_10m=2)
        detector = MailDetector(thresholds, TrafficAnalytics())
        record = LogRecord(
            category="mail",
            pattern="/var/log/exim_mainlog",
            path="/var/log/exim_mainlog",
            line="2026-04-22 10:00:00 1abcde-000000 => user@example.com A=dovecot_login:sender@example.com [203.0.113.10]",
        )
        self.assertEqual(await detector.detect(record), [])
        findings = await detector.detect(record)
        self.assertEqual(findings[0].event_type, "mail_abuse")

    async def test_api_detector_flags_abuse(self) -> None:
        thresholds = ThresholdSettings(api_calls_per_5m=2)
        detector = APIDetector(thresholds, TrafficAnalytics())
        record = LogRecord(
            category="cpanel",
            pattern="/usr/local/cpanel/logs/api_log",
            path="/usr/local/cpanel/logs/api_log",
            line="user=demo remote_ip=203.0.113.55 endpoint=listaccts",
        )
        self.assertEqual(await detector.detect(record), [])
        findings = await detector.detect(record)
        self.assertEqual(findings[0].event_type, "api_abuse")

    async def test_connection_flood_detector_flags_port_abuse(self) -> None:
        thresholds = ThresholdSettings(concurrent_connection_threshold=2)
        detector = ConnectionFloodDetector(thresholds, app_port=8443)

        class Addr:
            def __init__(self, ip: str, port: int):
                self.ip = ip
                self.port = port

        class Connection:
            def __init__(self, remote_ip: str):
                self.laddr = Addr("203.0.113.25", 8443)
                self.raddr = Addr(remote_ip, 55000)
                self.status = "ESTABLISHED"

        original = __import__("psutil").net_connections
        import psutil
        psutil.net_connections = lambda kind="inet": [Connection("198.51.100.44"), Connection("198.51.100.44")]
        try:
            findings = await detector.run_scan()
        finally:
            psutil.net_connections = original
        self.assertEqual(findings[0].event_type, "ddos_connection_flood")
        self.assertEqual(findings[0].ip, "198.51.100.44")


if __name__ == "__main__":
    unittest.main()
