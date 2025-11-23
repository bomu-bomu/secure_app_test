# Vulnerable Sinatra Demo

This intentionally insecure Sinatra application demonstrates common issues from `checklist.txt`.

## Setup

```bash
cd vulnerable_app
bundle install
ruby app.rb
```

The app uses an SQLite database stored at `db/insecure.db`. See `db/schema.sql` for structure.

### Demo credentials
Database seeds include a few intentionally weak accounts:

| Username | Password |
| --- | --- |
| `admin` | `admin123` |
| `alice` | `password` |
| `bob` | `123456` |

Use these to explore spoofing, elevation of privilege, IDOR, and other issues noted in `checklist.txt`.
