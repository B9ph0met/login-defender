# Login Defender

A multi-layered anti-bot login system that detects and blocks automated traffic before credential validation. Built with Flask and vanilla JavaScript.

## What It Does

This system uses five detection layers to identify bots attempting to brute force or credential stuff your login:

1. **Behavioral Timing** - Measures how fast users interact with the page (bots submit instantly)
2. **Headless Detection** - Checks for automation framework signatures (Selenium, Puppeteer)
3. **Browser Fingerprinting** - Generates a device hash to detect identity switching
4. **Rate Limiting** - Max 5 login attempts per IP+username in 5 minutes
5. **IP Reputation** - Checks against known malicious IPs (optional, requires API key)

Each layer contributes to a bot score. Requests scoring 60+ points are blocked before password validation.

## Quick Start

```bash
# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate secret key
python -c "import secrets; print(secrets.token_hex(32))"
# Add the output to .env as SECRET_KEY

# Run
python run.py
```

Visit http://localhost:5000 and login with `demo` / `password`.

## Project Structure

```
login-defender/
├── app/
│   ├── routes.py          # Login endpoint
│   ├── anti_bot_logic.py  # 5-layer scoring engine
│   └── database.py        # SQLite rate limiting
├── static/
│   ├── index.html         # Login form
│   └── js/
│       └── sentinel.js    # Client-side detection
└── run.py                 # Entry point
```

## How It Works

When a user submits the login form, the client-side JavaScript (`sentinel.js`) collects behavioral data, checks for headless browser flags, and generates a fingerprint. This data is sent as hidden form fields to the server.

The server (`anti_bot_logic.py`) analyzes all five layers, calculates a total bot score, and either blocks the request or validates credentials.

## Testing

**Normal login (should pass):**
- Open the page, wait 2 seconds, type slowly, submit
- Expected: Low bot score, login succeeds

**Headless browser (should block):**
```python
from selenium import webdriver
driver = webdriver.Chrome()
driver.get('http://localhost:5000')
# navigator.webdriver flag triggers +100 points
```

**Rate limiting (should block after 5 attempts):**
```bash
for i in {1..6}; do
  curl -X POST http://localhost:5000/login \
    -d "username=demo&password=wrong"
done
```

## Configuration

Edit `.env`:
```bash
SECRET_KEY=your-generated-key
IP_REPUTATION_API_KEY=optional-api-key
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=300
```

Adjust bot score threshold in `app/__init__.py`:
```python
app.config['BOT_SCORE_THRESHOLD'] = 60
```

## Security Notes

This is a demonstration project. For production use:

- Implement proper password hashing (currently uses hardcoded demo/password)
- Add CSRF protection
- Use HTTPS
- Remove debug endpoints (`/stats`, `/debug/analysis`)
- Set secure session cookie flags
- Add proper logging

## Debug Endpoints

**View statistics:**
```bash
curl http://localhost:5000/stats
```

**Test bot scoring:**
```bash
curl -X POST http://localhost:5000/debug/analysis \
  -d "username=test" \
  -d "sentinel_timing=0" \
  -d "sentinel_headless=100"
```

Remove these before deploying to production.

## License

MIT
