# CyberShield — Phishing Awareness and URL Checker

CyberShield is a responsive, educational web app for practicing how to spot common warning signs in a URL. It was created as a student project for the Honeywell Future Skills cybersecurity program.

## What it does

- Accepts and validates complete `http://` or `https://` URLs.
- Checks URL text for a small set of warning signs:
  - `@` symbols in the URL authority, which can disguise the actual host.
  - IP-address hosts.
  - Potentially misleading domain structures, including nested domain endings and known brand names on unrelated hosts.
  - Common lure words such as `verify`, `login`, `urgent`, and `otp`.
  - Plain HTTP connections.
- Explains each observed pattern and suggests safer next steps.
- Includes three clickable examples.
- Provides short awareness guidance about phishing, OTP scams, and safe browsing.

## Run locally

Requirements: Python 3.11 or newer and pip.

```bash
python -m venv .venv
```

Activate the environment, then install the packages:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

On Replit, use the **CyberShield** run workflow or run:

```bash
python app.py
```

The app listens on `0.0.0.0` and uses the `PORT` environment variable when provided.

## Test

```bash
python -m unittest discover -s tests -v
```

The tests cover input validation, warning-sign detection, the Flask API, the home page, and the health endpoint.

## Publish on Replit

1. Open the project's **Publish** or **Deploy** control.
2. Choose an Autoscale web deployment for this stateless Flask app. The CyberShield web artifact is configured to build the Python app and serve it with Gunicorn.
3. Set the app's visibility to **Public** if you want anyone with the link to access it.
4. Publish, then copy the public `*.replit.app` URL shown by Replit.

The app does not require API keys, paid APIs, a database, or external integrations.

## Technologies

- Python 3
- Flask
- Gunicorn for production serving
- HTML, CSS, and browser JavaScript
- Python standard library URL parsing and IP address validation

## Limitations and safety

CyberShield is a learning aid, not a security product. It uses simple, explainable rules; it does not open the submitted URL, inspect page content, resolve DNS, or query a live threat-intelligence database. Its domain-structure checks are heuristics and can produce false positives or miss harmful URLs. A URL with no detected warning signs is **not** confirmed safe, and this checker cannot guarantee whether any URL is safe.

Never enter a password, OTP, payment detail, or recovery code after following an unexpected link. Verify requests through an organization's official app, a saved bookmark, or a contact method you already trust.
