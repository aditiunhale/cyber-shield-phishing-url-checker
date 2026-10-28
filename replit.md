# CyberShield

A responsive phishing-awareness site with a Flask URL checker that explains common warning signs without opening the submitted URL.

## Run & Operate

- Run the `Project` workflow to start CyberShield on port 5000.
- `python -m unittest discover -s tests -v` — run the Python test suite.
- `pip install -r requirements.txt` — install Flask and Gunicorn.
- No database, API key, or external integration is required.

## Stack

- Python 3, Flask, and Gunicorn
- HTML templates, CSS, and browser JavaScript
- Python standard-library URL parsing and IP address validation
- Existing workspace starter packages remain under `artifacts/` and `lib/`.

## Where things live

- `app.py` — Flask page, health, and JSON check endpoints.
- `url_checker.py` — input validation and explainable rule-based checks.
- `templates/index.html` — accessible single-page interface and awareness guide.
- `static/styles.css`, `static/app.js` — responsive styling and browser interactions.
- `tests/test_url_checker.py` — backend and endpoint tests.
- `README.md` — local setup, testing, publishing steps, and limitations.

## Product

Users can check URL text for `@` symbols, IP-address hosts, misleading domain structures, suspicious keywords, and non-HTTPS connections. The app gives a short explanation and recommended next steps, with awareness guidance for phishing, OTP scams, and safe browsing.

## Gotchas

- This is a rule-based teaching aid, not a verdict: it does not visit URLs or query live threat intelligence.
- Keep any future URL analysis offline unless the product requirements explicitly change; submitted URLs are user-controlled input.
- The Flask server listens on `0.0.0.0` and uses `PORT` when provided by the runtime.
