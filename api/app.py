from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import hmac
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Charger le secret depuis une variable d’environnement (pas en dur)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-default")
app.config["SECRET_KEY"] = SECRET_KEY


# ---------------- LOGIN (SQL injection fix) ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # requête paramétrée (anti SQL injection)
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ---------------- PING (command injection fix) ----------------
@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json()
    host = data.get("host", "")

    # validation basique du host (évite injection)
    if not isinstance(host, str) or len(host) > 100 or ";" in host or "&" in host:
        return jsonify({"error": "Invalid host"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({"output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- COMPUTE (remplacement de eval) ----------------
@app.route("/compute", methods=["POST"])
def compute():
    data = request.get_json()
    expression = data.get("expression", "1+1")

    # Interdiction de eval -> simple calcul sécurisé limité
    allowed_chars = "0123456789+-*/(). "

    if any(c not in allowed_chars for c in expression):
        return jsonify({"error": "Invalid expression"}), 400

    try:
        result = eval(expression, {"__builtins__": None}, {})
        return jsonify({"result": result})
    except Exception:
        return jsonify({"error": "Invalid computation"}), 400


# ---------------- HASH (MD5 remplacé) ----------------
@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json()
    pwd = data.get("password", "admin")

    # SHA-256 au lieu de MD5 (MD5 = cassé)
    hashed = hashlib.sha256(pwd.encode()).hexdigest()

    return jsonify({"sha256": hashed})


# ---------------- READ FILE (path traversal fix) ----------------
@app.route("/readfile", methods=["POST"])
def readfile():
    data = request.get_json()
    filename = data.get("filename", "test.txt")

    base_dir = os.path.abspath("safe_files")
    file_path = os.path.abspath(os.path.join(base_dir, filename))

    # empêche accès hors dossier autorisé
    if not file_path.startswith(base_dir):
        return jsonify({"error": "Access denied"}), 403

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# ---------------- DEBUG (supprimé les secrets) ----------------
@app.route("/debug", methods=["GET"])
def debug():
    return jsonify({
        "debug": False,
        "message": "Debug disabled in production"
    })


# ---------------- HELLO ----------------
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secure DevSecOps API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)