# Architecture

## 1. Platform Goals

The platform is designed for busy WHM/cPanel servers with 1000+ hosted domains.
It combines:

- real-time log tailing
- rule-based threat detection
- lightweight anomaly scoring
- automated response
- operator dashboard and alerts

## 2. Processing Model

1. `LogTailer` discovers files from all configured patterns and tails them in
   near real time.
2. Each raw line is published to the in-memory event bus for the dashboard log
   viewer.
3. `DetectionEngine` passes the record through all detector modules.
4. Detector findings are enriched with GeoIP and optional AbuseIPDB context.
5. Findings are persisted in the database and sent to live dashboard streams.
6. `BanManager` decides whether to warn, rate-limit, temporarily ban, or
   permanently ban the source.
7. `EmailAlertService` sends actionable alerts to admins and client recipients.
8. Scheduled scanners run host-level checks that are not log-line driven:
   malware scanning, Node.js process inspection, and resource abuse checks.

## 3. Key Components

### `core/`

- `config.py`: YAML-backed settings model with sane defaults
- `database.py`: SQLAlchemy async engine and session management
- `models.py`: persistent state for users, events, bans, recipients, baselines
- `event_bus.py`: pub/sub queues for live event and log streams
- `log_tailer.py`: efficient polling tailer with rotation awareness
- `analytics.py`: rolling counters and EWMA anomaly helpers
- `metrics.py`: CPU, memory, disk, and socket telemetry
- `engine.py`: orchestration of tailers, detectors, responders, and alerts

### `detectors/`

- authentication brute force
- web exploit and WordPress abuse
- mail abuse and outbound spam
- WHM/cPanel API abuse
- ModSecurity parsing
- PHP malware and file integrity
- Node.js and process abuse
- system and resource anomalies

### `responders/`

- whitelist-aware ban manager
- dynamic ban escalation
- CSF integration with `iptables` fallback

### `alerts/`

- SMTP alert fanout
- optional AbuseIPDB enrichment

### `api/` and `dashboard/`

- FastAPI JSON API
- SSE live streams
- cookie-based JWT auth with CSRF enforcement
- single-page dashboard optimized for low-overhead operations

## 4. Detection Strategy

The engine intentionally mixes exact rules and stateful heuristics:

- regex and parser-driven rules for known patterns
- rolling per-IP/service thresholds for brute force and spam
- EWMA-based request spike detection for traffic surges
- file-integrity style comparison for changed PHP files
- process and port inspection for Node.js abuse

This avoids trying to force every problem into either pure regex or pure ML.

## 5. Performance Design

- Tail only files that currently exist; refresh discovery on an interval
- Read appended bytes instead of re-reading whole files
- Use bounded in-memory queues for live streaming
- Keep detector state in memory for hot-path decisions
- Batch expensive host scans on intervals
- Limit PHP scans to recently changed files per cycle
- Keep the dashboard query path separate from log ingestion

## 6. Security Design

- bcrypt password hashing
- signed JWT access tokens in secure cookies
- CSRF token validation for state-changing endpoints
- strict input validation with Pydantic
- dashboard auth on every protected route
- no shell execution from API input
- whitelist protection before auto-bans
- systemd hardening controls in deployment unit

## 7. Deployment Model

The default deployment targets `/opt/security-platform` with:

- app code
- Python virtualenv
- `/etc/security-platform/config.yml`
- SQLite database in `/var/lib/security-platform`
- logs in `/var/log/security-platform`

The service can later be split into separate collector and UI processes if a
multi-node design is needed.
