"""
app.py  —  Flask REST API
GET  /                   -> index.html
POST /api/auth/register  -> Dang ky
POST /api/auth/login     -> Dang nhap
GET  /api/users          -> Danh sach nguoi dung
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, hashlib, os, hmac, re, uuid

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
app       = Flask(__name__)
CORS(app)
DB_NAME   = os.path.join(BASE_DIR, "users.db")

# ── Route goc ──────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

# ── Tien ich ───────────────────────────────────────
def generate_salt():
    return os.urandom(32).hex()

def hash_pw(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def verify_pw(password, salt, stored):
    return hmac.compare_digest(hash_pw(password, salt).encode(), stored.encode())

def validate_pw(pw):
    e = []
    if len(pw) < 8:               e.append("Toi thieu 8 ky tu")
    if not re.search(r"[A-Z]",pw): e.append("Can chu hoa A-Z")
    if not re.search(r"[a-z]",pw): e.append("Can chu thuong a-z")
    if not re.search(r"\d",pw):    e.append("Can chu so 0-9")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]',pw): e.append("Can ky tu dac biet")
    return e

def json_body(*fields):
    d = request.get_json(silent=True)
    if not d:
        return None,(jsonify({"success":False,"message":"Body phai la JSON"}),400)
    miss = [f for f in fields if not d.get(f)]
    if miss:
        return None,(jsonify({"success":False,"message":f"{', '.join(miss)} bat buoc"}),400)
    return d, None

# ── Init DB ────────────────────────────────────────
def init_db():
    c = sqlite3.connect(DB_NAME)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    )""")
    c.commit(); c.close()
    print(f"[*] DB san sang: {DB_NAME}")

# ── POST /api/auth/register ────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    d,e = json_body("username","password")
    if e: return e
    u,p = d["username"].strip(), d["password"]
    if not re.match(r"^[a-zA-Z0-9_]{3,30}$",u):
        return jsonify({"success":False,"message":"Username khong hop le"}),400
    errs = validate_pw(p)
    if errs:
        return jsonify({"success":False,"message":"Mat khau khong du manh","errors":errs}),400
    salt = generate_salt()
    ph   = hash_pw(p,salt)
    try:
        con=sqlite3.connect(DB_NAME); cur=con.cursor()
        cur.execute("INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",(u,ph,salt))
        uid=cur.lastrowid; con.commit()
    except sqlite3.IntegrityError:
        return jsonify({"success":False,"message":"Username da duoc su dung"}),409
    except:
        return jsonify({"success":False,"message":"Loi he thong"}),500
    finally:
        con.close()
    return jsonify({"success":True,"message":"Dang ky thanh cong","user_id":uid}),201

# ── POST /api/auth/login ───────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    d,e = json_body("username","password")
    if e: return e
    u,p = d["username"].strip(), d["password"]
    try:
        con=sqlite3.connect(DB_NAME); cur=con.cursor()
        cur.execute("SELECT password_hash,salt FROM users WHERE username=?",(u,))
        row=cur.fetchone()
    except:
        return jsonify({"success":False,"message":"Loi he thong"}),500
    finally:
        con.close()
    if row is None or not verify_pw(p,row[1],row[0]):
        return jsonify({"success":False,"message":"Sai thong tin dang nhap"}),401
    token=str(uuid.uuid4()).replace("-","")
    return jsonify({"success":True,"message":"Dang nhap thanh cong","token":token}),200

# ── GET /api/users ─────────────────────────────────
@app.route("/api/users", methods=["GET"])
def get_users():
    try:
        con=sqlite3.connect(DB_NAME); cur=con.cursor()
        cur.execute("SELECT id,username,password_hash,salt,created_at FROM users ORDER BY id DESC")
        rows=cur.fetchall()
    except:
        return jsonify({"success":False,"message":"Loi he thong"}),500
    finally:
        con.close()
    users=[{"id":r[0],"username":r[1],"password_hash":r[2][:12]+"…","salt":r[3][:8]+"…","created_at":r[4]} for r in rows]
    return jsonify({"success":True,"count":len(users),"users":users}),200

if __name__=="__main__":
    init_db()
    print("[*] Mo trinh duyet: http://localhost:5000")
    app.run(debug=True, port=5000)