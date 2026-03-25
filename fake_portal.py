"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Dummy Login Portal (Credential Stuffing Target)
 Run on victim VM: python3 fake_portal.py
 Environment: ISOLATED VM LAB ONLY
====================================================

A minimal Flask web app with a /login endpoint.
The IDS behavioral engine monitors POST requests
to this endpoint to detect credential stuffing via
CV-based timing analysis.
"""

import time
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="[PORTAL %(asctime)s] %(message)s", datefmt="%H:%M:%S")

# Fake user database
USERS = {
    "alice@example.com":  "correct_password_1",
    "bob@example.com":    "correct_password_2",
    "admin@example.com":  "securePass123!",
}

# Log all login attempts for IDS analysis
attempt_log = []

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>MyApp Login</title>
<style>
  body { font-family: Arial; max-width: 400px; margin: 100px auto; }
  input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
  button { width: 100%; padding: 10px; background: #2980B9; color: white; border: none; cursor: pointer; }
</style>
</head>
<body>
  <h2>Login to MyApp</h2>
  <form method="POST" action="/login">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    email    = request.form.get("email", "") or request.json.get("email", "") if request.is_json else request.form.get("email", "")
    password = request.form.get("password", "") or (request.json.get("password", "") if request.is_json else request.form.get("password", ""))

    timestamp = time.time()
    src_ip    = request.remote_addr
    success   = USERS.get(email) == password

    # Log attempt
    entry = {
        "ts": timestamp,
        "src": src_ip,
        "email": email,
        "success": success,
        "dt": datetime.now().isoformat()
    }
    attempt_log.append(entry)
    logging.info(f"LOGIN ATTEMPT | src={src_ip} | email={email} | success={success}")

    if success:
        return jsonify({"status": "success", "message": "Welcome!"})
    else:
        time.sleep(0.1)  # small delay to simulate DB lookup
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

@app.route("/attempts")
def view_attempts():
    """Admin endpoint to view all login attempt logs (for IDS graph data)."""
    recent = attempt_log[-100:]
    return jsonify({
        "total_attempts": len(attempt_log),
        "recent": recent,
        "success_count": sum(1 for a in attempt_log if a["success"]),
        "fail_count":    sum(1 for a in attempt_log if not a["success"])
    })

if __name__ == "__main__":
    print("=" * 50)
    print(" Fake Login Portal - AUA Botnet Research Lab")
    print(" Listening on 0.0.0.0:80")
    print(" Monitor /attempts for IDS data")
    print("=" * 50)
    app.run(host="0.0.0.0", port=80, debug=False)
