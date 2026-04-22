# Security Platform

Enterprise-grade security monitoring, threat detection, and response platform
for WHM/cPanel fleets hosting WordPress, PHP, and Node.js applications on
AlmaLinux, RHEL, Rocky Linux, and CentOS.

## Highlights

- Real-time multi-source log monitoring
- Stateful detection engine for brute force, web attacks, mail abuse, API abuse,
  and ModSecurity alerts
- PHP malware scanning and Node.js process abuse checks
- Automated response with CSF first and `iptables` fallback
- FastAPI dashboard with live event and log streaming
- SQLite by default with a schema ready for PostgreSQL migration
- SMTP alerts, recipient management, GeoIP hooks, and AbuseIPDB enrichment

## Default Layout

- `core/`: runtime, config, storage, streaming, analytics, and shared services
- `detectors/`: log and host-level threat detection modules
- `responders/`: firewall and automated response logic
- `alerts/`: SMTP delivery and AbuseIPDB enrichment
- `api/`: FastAPI application and routes
- `dashboard/`: HTML, CSS, and browser-side dashboard logic
- `config/`: deployment configuration templates
- `systemd/`: service unit

## Quick Start

1. Copy [config/security-platform.example.yml](/Users/hemantsingh/Documents/Codex/2026-04-22-you-are-a-principal-cybersecurity-architect/config/security-platform.example.yml) to `/etc/security-platform/config.yml`
2. Install dependencies with `uv pip install .` or `pip install .`
3. Initialize the database:

```bash
python -m core.cli init-db
python -m core.cli create-admin --username admin
```

4. Start the API:

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8443
```

5. Open `https://server:8443/`

## Production Notes

- Run behind TLS or terminate TLS at a trusted reverse proxy
- Use CSF where available; the platform falls back to `iptables`
- Configure whitelist IPs before enabling auto-bans
- For very large fleets, move to PostgreSQL and increase scanner intervals
