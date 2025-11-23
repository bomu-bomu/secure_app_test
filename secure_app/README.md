# Secure Sinatra Demo

This Sinatra application demonstrates mitigations for the issues listed in `../checklist.txt`. It enforces secure defaults, parameterized queries, CSRF protection, strict headers, rate limiting, and safe file handling.

## Setup

```bash
cd secure_app
bundle install
ruby app.rb
```

The app stores data in `db/secure.db`. See `db/schema.sql` for details.
