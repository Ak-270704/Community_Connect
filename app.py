import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "community.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
# For production, set an environment SECRET_KEY in Render. Fallback for local dev:
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_change_this")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DATABASE"] = DB_PATH

# ✅ Make datetime available in all templates
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# --- DB helpers ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(app.config["DATABASE"])
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        appt_date TEXT NOT NULL,
        appt_time TEXT NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()

# Initialize DB on import (safe small operation)
init_db()

# --- Auth helpers ---
def get_user_by_email(email):
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cur.fetchone()

def get_user_by_id(user_id):
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

# --- Routes ---
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/book", methods=["GET", "POST"])
@login_required
def book():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        appt_date = request.form.get("date", "").strip()
        appt_time = request.form.get("time", "").strip()
        reason = request.form.get("reason", "").strip()

        if not (name and email and appt_date and appt_time):
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("book"))

        db = get_db()
        db.execute(
            "INSERT INTO appointments (user_id, name, email, appt_date, appt_time, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session.get("user_id"), name, email, appt_date, appt_time, reason, datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Appointment booked successfully.", "success")
        return redirect(url_for("book"))

    # Show user's appointments
    db = get_db()
    cur = db.execute("SELECT * FROM appointments WHERE user_id = ? ORDER BY created_at DESC", (session.get("user_id"),))
    appointments = cur.fetchall()
    return render_template("book.html", appointments=appointments)

@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    db = get_db()
    if request.method == "POST":
        if "user_id" not in session:
            flash("Please log in to post a review.", "warning")
            return redirect(url_for("login"))

        name = request.form.get("name", "").strip()
        rating = request.form.get("rating", "").strip()
        comment = request.form.get("comment", "").strip()
        if not (name and rating):
            flash("Please provide your name and a rating.", "danger")
            return redirect(url_for("reviews"))

        db.execute(
            "INSERT INTO reviews (user_id, name, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
            (session.get("user_id"), name, int(rating), comment, datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Thanks for your review!", "success")
        return redirect(url_for("reviews"))

    cur = db.execute("SELECT r.*, u.email as user_email FROM reviews r LEFT JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC")
    reviews = cur.fetchall()
    return render_template("reviews.html", reviews=reviews)

# --- Auth routes ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not (name and email and password):
            flash("Please fill all fields.", "danger")
            return redirect(url_for("register"))

        if get_user_by_email(email):
            flash("An account with that email already exists.", "warning")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        db = get_db()
        db.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, email, password_hash, datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# --- Simple user dashboard (optional) ---
@app.route("/profile")
@login_required
def profile():
    user = get_user_by_id(session.get("user_id"))
    return render_template("profile.html", user=user)

# --- Run (for local dev) ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
