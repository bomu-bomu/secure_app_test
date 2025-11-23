# Security Assessment Playground

This repository now contains two Sinatra + SQLite3 subprojects tied to `checklist.txt`:

1. `vulnerable_app/` – deliberately insecure implementation that demonstrates the STRIDE issues in the checklist. Use it to reproduce attacks.
2. `secure_app/` – hardened implementation that mitigates the same items with proper authentication, authorization, validations, secure headers, CSRF protection, rate limiting, and safe file handling.

## Getting Started

### Prerequisites
- Ruby 3.x
- Bundler (`gem install bundler`)
- SQLite3 CLI (for inspecting the databases)
- Optional: Redis (only needed if you want Rack::Attack to use Redis; otherwise in-memory throttling is used)

### Running the Vulnerable Demo
```bash
cd vulnerable_app
bundle install
ruby app.rb
# App listens on http://localhost:4567
```
The app auto-creates `db/insecure.db` and seeds plaintext users/comments. Try the flows listed on the home page to map directly to `checklist.txt` entries (spoofing, tampering, IDOR, stored XSS, unrestricted uploads, forced browsing, etc.).

### Running the Secure Demo
```bash
cd secure_app
bundle install
ruby app.rb
# App listens on http://localhost:4567
```
Environment variables:
- `SESSION_SECRET` – supply a strong value in production
- `REDIS_URL` – optional Redis connection string for Rack::Attack cache

### Robot Framework functional exploits
The `robot_tests/vulnerable_app_exploits.robot` suite shows how a generic functional test tool can exercise multiple checklist items (SQL injection, stored XSS, unrestricted upload, IDOR) without requiring specialized scanners.

#### Install Robot Framework
You can install globally with `pipx` or inside a virtualenv. Example using `pip`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install robotframework robotframework-requests requests
```

> **Note**: modern Robot Framework uses the `robot` CLI. Older tutorials reference `pybot`, which has been removed.

#### Run the exploit suite

```bash
export VULN_BASE_URL=http://localhost:4567   # optional override, defaults to this value
robot robot_tests/vulnerable_app_exploits.robot
```

Expected results: tests should **pass** against `vulnerable_app` (demonstrating the insecurity) and **fail** against `secure_app`.

The secure app enforces:
- Strong password policy and hashed credentials (AUTH-001)
- Role-based access control for admin endpoints (EoP mitigations)
- Parameterized SQL queries (INPUT-001/002)
- Rack::Protection + CSRF tokens (INPUT-003)
- Strict security headers & CSP (HEAD-001)
- Rate limiting via Rack::Attack (API-001 / DoS mitigations)
- Sanitized file uploads (FILE-001/002) and encoded comments to prevent XSS
- Least-privilege session handling, safe logging, and informative-but-safe error messages

## Mapping to `checklist.txt`
Use the checklist lines as a guide:
- Run attacks against `vulnerable_app` to see how each item can be exploited.
- Repeat against `secure_app` to confirm mitigations; most tests in `tests/test_security_assessment.py` expect a hardened target.

Feel free to expand each subproject with more scenarios or hook CI to run automated checks against the secure implementation.
