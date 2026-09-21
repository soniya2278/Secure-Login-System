from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)

# Secret key used for sessions
app.secret_key = "change-this-to-a-random-secret-key"


# Create database and table
def init_db():
    conn = sqlite3.connect("users.db")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        # Basic validation
        if len(username) < 3:
            return "Username must contain at least 3 characters."

        if len(password) < 8:
            return "Password must contain at least 8 characters."

        # Hash password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            conn = sqlite3.connect("users.db")

            # Parameterized query prevents SQL injection
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password.decode("utf-8"))
            )

            conn.commit()
            conn.close()

            return redirect("/login")

        except sqlite3.IntegrityError:
            return "Username already exists."

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")

        user = conn.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user:
            stored_password = user[2]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password.encode("utf-8")
            ):

                session["user_id"] = user[0]
                session["username"] = user[1]

                return redirect("/dashboard")

        return "Invalid username or password."

    return render_template("login.html")


# Protected dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# Logout
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run()
