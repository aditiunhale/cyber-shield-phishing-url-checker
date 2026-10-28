"""CyberShield Flask application."""

import os

from flask import Flask, jsonify, render_template, request

from url_checker import URLValidationError, check_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/healthz")
def health():
    return jsonify({"status": "ok"})


@app.post("/check")
def api_check():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Send a JSON object containing a URL."}), 400

    try:
        result = check_url(payload.get("url"))
    except URLValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
