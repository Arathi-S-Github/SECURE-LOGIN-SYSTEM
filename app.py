from flask import Flask, request, redirect, session, url_for, render_template_string
import sqlite3
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "secret"
bcrypt = Bcrypt(app)

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.commit()
    conn.close()

init_db()

def valid(username, password):
    return re.match(r"^[a-zA-Z0-9_]+$", username) and len(password) >= 6

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (u,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], p):
            session["user"] = u
            return redirect("/dashboard")

        return "Invalid login"

    return render_template_string("""
    <form method="POST">
    <input name="username" placeholder="Username"><br>
    <input type="password" name="password"><br>
    <button>Login</button>
    </form>
    <a href="/register">Register</a>
    """)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        if not valid(u,p):
            return "Invalid input"

        hp = bcrypt.generate_password_hash(p).decode()

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username,password) VALUES (?,?)",(u,hp))
            conn.commit()
            conn.close()
            return redirect("/")
        except:
            return "User exists"

    return render_template_string("""
    <form method="POST">
    <input name="username"><br>
    <input type="password" name="password"><br>
    <button>Register</button>
    </form>
    """)

@app.route("/dashboard")
def dash():
    if "user" not in session:
        return redirect("/")
    return f"Welcome {session['user']} <a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.pop("user",None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
