from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
from werkzeug.security import generate_password_hash
import ast
app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret")  # Hardcoded secret


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()
    if result:
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    result = subprocess.check_output(
        ["ping", "-c", "1", host],
        text=True
    )

    return {"output": result}


@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")
    try:
        result = ast.literal_eval(expression)
        return {"result": result}
    except:
        return {"error": "invalid expression"}


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    hashed = generate_password_hash(pwd)
    return {"password_hash": hashed}


@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")
    if ".." in filename:
        return {"error": "invalid filename"}

    with open(filename, "r") as f:
        content = f.read()

    return {"content": content}


@app.route("/debug", methods=["GET"])
def debug():
    # Renvoie des détails sensibles -> mauvaise pratique
    return {"error": "forbidden"}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps vulnerable API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)