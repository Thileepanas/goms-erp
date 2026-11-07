from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    send_file, jsonify
)
import sqlite3
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
import pandas as pd
import requests
import csv
import io

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "goms_erp_new.db")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "goms-local-development-key-change-before-deployment")

if not os.environ.get("FLASK_SECRET_KEY"):
    print("WARNING: Using default Flask secret key. Set FLASK_SECRET_KEY before deploying!")

app.permanent_session_lifetime = timedelta(minutes=30)

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ------------------------------------------------------------------
# TEMPLATE FILTERS
# ------------------------------------------------------------------
@app.template_filter('dateformat')
def dateformat(value, format='%d/%m/%Y'):
    if not value: return "-"
    try: return datetime.strptime(value, '%Y-%m-%d').strftime(format)
    except: return value

@app.template_filter('inr')
def format_inr(number):
    if number is None: return "0.00"
    try: number = float(number)
    except: return "0.00"
    is_negative = False
    if number < 0:
        is_negative = True
        number = abs(number)
    s = f"{number:.2f}"
    integer_part, decimal_part = s.split(".")
    if len(integer_part) > 3:
        last_three = integer_part[-3:]
        remaining = integer_part[:-3]
        groups = []
        while len(remaining) > 2:
            groups.insert(0, remaining[-2:])
            remaining = remaining[:-2]
        if remaining: groups.insert(0, remaining)
        formatted_integer = ",".join(groups) + "," + last_three
    else: formatted_integer = integer_part
    result = formatted_integer + "." + decimal_part
    if is_negative: result = "-" + result
    return result

def num_to_words(num):
    units = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]
    def two_digit(n):
        if n < 20: return units[n]
        return tens[n // 10] + (" " + units[n % 10] if n % 10 != 0 else "")
    def three_digit(n):
        if n < 100: return two_digit(n)
        return units[n // 100] + " Hundred" + (" and " + two_digit(n % 100) if n % 100 != 0 else "")
    parts = f"{num:.2f}".split(".")
    rupees, paise = int(parts[0]), int(parts[1])
    words = ""
    if rupees == 0: words = "Zero"
    else:
        if rupees >= 10000000: words += two_digit(rupees // 10000000) + " Crore "; rupees %= 10000000
        if rupees >= 100000: words += two_digit(rupees // 100000) + " Lakh "; rupees %= 100000
        if rupees >= 1000: words += two_digit(rupees // 1000) + " Thousand "; rupees %= 1000
        if rupees > 0: words += three_digit(rupees)
    words = "Rupees " + words.strip()
    if paise > 0: words += " and " + two_digit(paise) + " Paise"
    return words + " Only."

# ------------------------------------------------------------------
# AUTH HELPERS & DB
# ------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None: salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
    return salt, password_hash

def verify_password(password, salt, expected_hash):
    _, actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'Admin')")
    conn.execute("CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, client_name TEXT NOT NULL, work_order TEXT, project_value REAL DEFAULT 0, start_date TEXT, status TEXT DEFAULT 'Planning')")
    conn.execute("CREATE TABLE IF NOT EXISTS purchases (id INTEGER PRIMARY KEY AUTOINCREMENT, po_number TEXT, project_name TEXT NOT NULL, supplier_name TEXT NOT NULL, invoice_number TEXT NOT NULL, invoice_date TEXT, material_description TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, subtotal REAL DEFAULT 0, gst_amount REAL DEFAULT 0, total_amount REAL DEFAULT 0, md_approval TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS purchase_items (id INTEGER PRIMARY KEY AUTOINCREMENT, purchase_id INTEGER NOT NULL, material_name TEXT, description TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS stock (id INTEGER PRIMARY KEY AUTOINCREMENT, material_code TEXT, material_name TEXT NOT NULL, unit TEXT, opening_stock REAL DEFAULT 0, stock_in REAL DEFAULT 0, stock_out REAL DEFAULT 0, reorder_level REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS stock_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, material_name TEXT NOT NULL, transaction_date TEXT, transaction_type TEXT NOT NULL, invoice_no TEXT, project_name TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS labour (id INTEGER PRIMARY KEY AUTOINCREMENT, labour_name TEXT NOT NULL, designation TEXT, daily_wage REAL DEFAULT 0, contact_number TEXT, join_date TEXT, project_name TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS labour_attendance (id INTEGER PRIMARY KEY AUTOINCREMENT, labour_id INTEGER NOT NULL, attendance_date TEXT NOT NULL, status TEXT NOT NULL, project_name TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, transaction_date TEXT, description TEXT NOT NULL, amount REAL DEFAULT 0, transaction_type TEXT NOT NULL, project_name TEXT, paid_name TEXT, category TEXT, bill_no TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS bills (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, bill_no TEXT NOT NULL, bill_date TEXT, total_value REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS bill_items (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL, description TEXT NOT NULL, hsn_sac TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, basic_amount REAL DEFAULT 0, gst_amount REAL DEFAULT 0, total_amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS parties (id INTEGER PRIMARY KEY AUTOINCREMENT, party_name TEXT NOT NULL, party_type TEXT NOT NULL, contact_number TEXT, email TEXT, gstin TEXT, address TEXT, opening_balance REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS poq (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, material_name TEXT NOT NULL, unit TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0, req_date TEXT, status TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS po (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, vendor_name TEXT NOT NULL, po_date TEXT, delivery_address TEXT, quotation_no TEXT, status TEXT DEFAULT 'Ordered', gm_approval TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS po_items (id INTEGER PRIMARY KEY AUTOINCREMENT, po_id INTEGER NOT NULL, material_name TEXT NOT NULL, hsn_code TEXT, quantity REAL DEFAULT 0, unit TEXT, rate REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS material_issues (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, issue_date TEXT, issued_to TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS material_issue_items (id INTEGER PRIMARY KEY AUTOINCREMENT, issue_id INTEGER NOT NULL, material_name TEXT NOT NULL, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS work_progress (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, boq_item_id INTEGER NOT NULL, work_date TEXT, qty_done REAL DEFAULT 0, remarks TEXT, is_billed INTEGER DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS gstr2b_data (id INTEGER PRIMARY KEY AUTOINCREMENT, supplier_gstin TEXT, supplier_name TEXT, invoice_number TEXT, invoice_date TEXT, total_value REAL DEFAULT 0, match_status TEXT DEFAULT 'Unmatched')")
    conn.execute("CREATE TABLE IF NOT EXISTS tenders (id INTEGER PRIMARY KEY AUTOINCREMENT, tender_no TEXT NOT NULL, client_name TEXT NOT NULL, tender_date TEXT, submission_date TEXT, status TEXT DEFAULT 'Pending', estimated_value REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS tender_items (id INTEGER PRIMARY KEY AUTOINCREMENT, tender_id INTEGER NOT NULL, description TEXT, unit TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, supply_rate REAL DEFAULT 0, erection_rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.commit()

    def add_column(table, column, col_type):
        try:
            cursor = conn.execute(f"PRAGMA table_info({table})")
            if column not in [info[1] for info in cursor.fetchall()]:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                conn.commit()
        except: pass

    # Add all required columns across all tables
    add_column("purchases", "md_approval", "TEXT DEFAULT 'Pending'")
    add_column("purchases", "approved_amount", "REAL DEFAULT 0")
    add_column("purchases", "payment_status", "TEXT DEFAULT 'Pending'")
    add_column("users", "role", "TEXT DEFAULT 'Admin'")
    add_column("poq", "unit", "TEXT")
    add_column("poq", "rate", "REAL")
    add_column("poq", "amount", "REAL")
    add_column("po_items", "unit", "TEXT")
    add_column("work_progress", "is_billed", "INTEGER DEFAULT 0")
    add_column("poq", "supply_rate", "REAL DEFAULT 0")
    add_column("poq", "erection_rate", "REAL DEFAULT 0")
    add_column("poq", "subcon_name", "TEXT")
    add_column("poq", "subcon_rate", "REAL DEFAULT 0")
    add_column("poq", "company_supply_rate", "REAL DEFAULT 0")
    add_column("poq", "company_erection_rate", "REAL DEFAULT 0")
    add_column("work_progress", "qty_supply", "REAL DEFAULT 0")
    add_column("work_progress", "qty_erection", "REAL DEFAULT 0")
    add_column("work_progress", "is_billed_supply", "INTEGER DEFAULT 0")
    add_column("work_progress", "is_billed_erection", "INTEGER DEFAULT 0")
    add_column("bill_items", "supply_rate", "REAL DEFAULT 0")
    add_column("bill_items", "erection_rate", "REAL DEFAULT 0")
    add_column("bills", "bill_type", "TEXT DEFAULT 'BOQ'")
    add_column("po", "gm_approval", "TEXT DEFAULT 'Pending'")
    add_column("accounts", "bill_no", "TEXT")
    add_column("tender_items", "supply_rate", "REAL DEFAULT 0")
    add_column("tender_items", "erection_rate", "REAL DEFAULT 0")

    indexes = ["CREATE INDEX IF NOT EXISTS idx_purchases_project ON purchases(project_name)", "CREATE INDEX IF NOT EXISTS idx_bills_project ON bills(project_name)", "CREATE INDEX IF NOT EXISTS idx_accounts_project ON accounts(project_name)", "CREATE INDEX IF NOT EXISTS idx_poq_project ON poq(project_name)", "CREATE INDEX IF NOT EXISTS idx_wp_project ON work_progress(project_name)"]
    for idx in indexes:
        try: conn.execute(idx)
        except: pass
    conn.commit()

    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        salt, pw = hash_password("ChangeMe@123")
        conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES ('admin', ?, ?, 'Admin')", (salt, pw))
        conn.commit()
    conn.close()

@app.before_request
def restrict_site_supervisor():
    if not session.get("username"): return
    if session.get("role") == "Site Supervisor":
        blocked = ['accounts', 'accounts_entry', 'delete_account_entry', 'delete_bill', 'print_bill', 'client_ledger', 'vendor_ledger', 'parties', 'delete_party', 'edit_party', 'users', 'delete_user', 'edit_user_role', 'backup', 'md_approval', 'md_approve', 'gst_reconciliation', 'run_reconciliation', 'vendor_report', 'purchases', 'edit_purchase', 'delete_purchase', 'gm_approval', 'gm_approve', 'po', 'edit_po', 'print_po', 'poq', 'delete_poq', 'tenders', 'tender_items', 'convert_tender', 'update_tender_status', 'reports', 'reports_export_csv', 'cost_control', 'pay_purchase_bill']
        if request.endpoint in blocked:
            flash("Access Denied.", "error"); return redirect(url_for('dashboard'))

# ------------------------------------------------------------------
# BASIC ROUTES
# ------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("username"): return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        conn = get_db(); user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone(); conn.close()
        if user and verify_password(password, user["salt"], user["password_hash"]):
            session.permanent = True; session["username"] = user["username"]; session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/dashboard")
def dashboard():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    d = {}
    d['total_projects'] = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    d['total_project_value'] = conn.execute("SELECT SUM(project_value) FROM projects").fetchone()[0] or 0
    d['total_sales'] = conn.execute("SELECT SUM(total_value) FROM bills").fetchone()[0] or 0
    d['total_labour'] = conn.execute("SELECT COUNT(*) FROM labour").fetchone()[0]
    
    d['total_income'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Income', 'Debit Note')").fetchone()[0] or 0
    d['total_expense'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Expense', 'Credit Note')").fetchone()[0] or 0
    
    d['low_stock_count'] = conn.execute("SELECT COUNT(*) FROM stock WHERE opening_stock <= reorder_level").fetchone()[0]
    d['pending_approvals'] = conn.execute("SELECT COUNT(*) FROM purchases WHERE md_approval='Pending'").fetchone()[0]
    d['pending_gm_approvals'] = conn.execute("SELECT COUNT(*) FROM po WHERE gm_approval='Pending'").fetchone()[0]
    d['recent_bills'] = conn.execute("SELECT * FROM bills ORDER BY id DESC LIMIT 5").fetchall()
    
    ps = conn.execute("SELECT COALESCE(status, 'Unknown') as status, COUNT(*) as count FROM projects GROUP BY status").fetchall()
    d['status_labels'] = [r['status'] for r in ps]; d['status_counts'] = [r['count'] for r in ps]
    conn.close()
    today = datetime.now(); fy = today.year if today.month >= 4 else today.year - 1
    return render_template("dashboard.html", **d, today=today, fy_str=f"{fy}-{(fy+1)%100:02d}")

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

# ------------------------------------------------------------------
# USERS & PASSWORDS
# ------------------------------------------------------------------
@app.route("/users", methods=["GET", "POST"])
def users():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        u, p, r = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("role", "Admin")
        if not u or not p: flash("Username/Password required.", "error")
        else:
            salt, pw = hash_password(p)
            try:
                conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)", (u, salt, pw, r))
                conn.commit(); flash(f"User '{u}' created!", "success")
            except sqlite3.IntegrityError: flash("Username exists!", "error")
        conn.close(); return redirect(url_for("users"))
    ul = conn.execute("SELECT id, username, role FROM users ORDER BY id DESC").fetchall()
    conn.close(); return render_template("users.html", users=ul)

@app.route("/users/delete/<int:id>")
def delete_user(id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") != "Admin": flash("Only Admin can delete.", "error"); return redirect(url_for("users"))
    conn = get_db(); target = conn.execute("SELECT username FROM users WHERE id=?", (id,)).fetchone()
    if target and target["username"] == session.get("username"): flash("Cannot delete yourself.", "error")
    else: conn.execute("DELETE FROM users WHERE id=?", (id,)); conn.commit(); flash("User deleted.", "success")
    conn.close(); return redirect(url_for("users"))

@app.route("/users/edit/<int:id>", methods=["POST"])
def edit_user_role(id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") != "Admin": return redirect(url_for("users"))
    conn = get_db(); conn.execute("UPDATE users SET role=? WHERE id=?", (request.form.get("role"), id)); conn.commit(); conn.close()
    flash("Role updated.", "success"); return redirect(url_for("users"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not session.get("username"): return redirect(url_for("login"))
    if request.method == "POST":
        old, new, confirm = request.form.get("old_password"), request.form.get("new_password"), request.form.get("confirm_password")
        if new != confirm: flash("Passwords do not match!", "error"); return redirect(url_for("change_password"))
        if len(new) < 6: flash("Password must be 6+ chars.", "error"); return redirect(url_for("change_password"))
        conn = get_db(); user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()
        if user and verify_password(old, user["salt"], user["password_hash"]):
            salt, pw_hash = hash_password(new)
            conn.execute("UPDATE users SET salt=?, password_hash=? WHERE id=?", (salt, pw_hash, user["id"]))
            conn.commit(); conn.close()
            flash("Password changed!", "success"); session.clear(); return redirect(url_for("login"))
        flash("Incorrect Old Password.", "error"); conn.close()
        return redirect(url_for("change_password"))
    return render_template("change_password.html")

# ------------------------------------------------------------------
# PROJECTS & TENDERS
# ------------------------------------------------------------------
@app.route("/projects", methods=["GET", "POST"])
def projects():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        p_name, c_name = request.form.get("project_name", "").strip(), request.form.get("client_name", "").strip()
        if p_name and c_name:
            conn.execute("INSERT INTO projects (project_name, client_name, work_order, project_value, start_date, status) VALUES (?, ?, ?, ?, ?, ?)", (p_name, c_name, request.form.get("work_order"), float(request.form.get("project_value") or 0), request.form.get("start_date"), request.form.get("status", "Planning")))
            conn.commit(); flash("Project saved!", "success"); conn.close(); return redirect(url_for("projects"))
    pl = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    d = conn.execute("SELECT party_name FROM parties WHERE party_type='Debtor' ORDER BY party_name").fetchall()
    conn.close(); return render_template("projects.html", projects=pl, debtors=d)

@app.route("/projects/delete/<int:id>")
def delete_project(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    p = conn.execute("SELECT project_name FROM projects WHERE id = ?", (id,)).fetchone()
    if p:
        p_name = p['project_name']
        conn.execute("DELETE FROM poq WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM work_progress WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM purchases WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM purchase_items WHERE purchase_id NOT IN (SELECT id FROM purchases)")
        conn.execute("DELETE FROM bills WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM bill_items WHERE bill_id NOT IN (SELECT id FROM bills)")
        conn.execute("DELETE FROM accounts WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM po WHERE project_name = ?", (p_name,))
        conn.execute("DELETE FROM po_items WHERE po_id NOT IN (SELECT id FROM po)")
        conn.execute("DELETE FROM projects WHERE id = ?", (id,))
        conn.commit()
        flash("Project and all related data deleted!", "success")
    conn.close(); return redirect(url_for("projects"))

@app.route("/projects/edit/<int:id>", methods=["GET", "POST"])
def edit_project(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        conn.execute("UPDATE projects SET project_name=?, client_name=?, work_order=?, project_value=?, start_date=?, status=? WHERE id=?", (request.form.get("project_name"), request.form.get("client_name"), request.form.get("work_order"), float(request.form.get("project_value") or 0), request.form.get("start_date"), request.form.get("status"), id))
        conn.commit(); flash("Project updated!", "success"); conn.close(); return redirect(url_for("projects"))
    p = conn.execute("SELECT * FROM projects WHERE id=?", (id,)).fetchone()
    d = conn.execute("SELECT party_name FROM parties WHERE party_type='Debtor' ORDER BY party_name").fetchall()
    conn.close(); return render_template("edit_project.html", project=p, debtors=d)

@app.route("/tenders", methods=["GET", "POST"])
def tenders():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        if request.form.get("tender_no") and request.form.get("client_name"):
            conn.execute("INSERT INTO tenders (tender_no, client_name, tender_date, submission_date) VALUES (?, ?, ?, ?)", (request.form.get("tender_no"), request.form.get("client_name"), request.form.get("tender_date"), request.form.get("submission_date")))
            conn.commit(); flash("Tender created!", "success"); return redirect(url_for("tenders"))
    tl = conn.execute("SELECT * FROM tenders ORDER BY id DESC").fetchall()
    conn.close(); return render_template("tenders.html", tenders=tl)

@app.route("/tender/<int:id>", methods=["GET", "POST"])
def tender_items(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        descs = request.form.getlist("description[]"); units = request.form.getlist("unit[]"); qtys = request.form.getlist("quantity[]"); sup_rates = request.form.getlist("supply_rate[]"); ere_rates = request.form.getlist("erection_rate[]")
        for i in range(len(descs)):
            if descs[i].strip():
                q, s_rate, e_rate = float(qtys[i] or 0), float(sup_rates[i] or 0), float(ere_rates[i] or 0)
                total_rate = s_rate + e_rate; amt = round(q * total_rate, 2)
                conn.execute("INSERT INTO tender_items (tender_id, description, unit, quantity, rate, supply_rate, erection_rate, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (id, descs[i], units[i], q, total_rate, s_rate, e_rate, amt))
        total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id = ?", (id,)).fetchone()[0] or 0
        conn.execute("UPDATE tenders SET estimated_value = ? WHERE id = ?", (total, id))
        conn.commit(); flash("Items added!", "success"); conn.close(); return redirect(url_for("tender_items", id=id))
    t = conn.execute("SELECT * FROM tenders WHERE id=?", (id,)).fetchone()
    items = conn.execute("SELECT * FROM tender_items WHERE tender_id=?", (id,)).fetchall()
    conn.close(); return render_template("tender_items.html", tender=t, items=items)

@app.route("/tender/<int:id>/upload_excel", methods=["POST"])
def upload_tender_excel(id):
    if not session.get("username"): return redirect(url_for("login"))
    file = request.files.get('excel_file')
    if not file or file.filename == '': flash("No file selected!", "error"); return redirect(url_for("tender_items", id=id))
    try:
        df = pd.read_excel(file)
        req_cols = ['Description', 'Quantity', 'Unit', 'Supply Rate', 'Erection Rate']
        if not all(col in df.columns for col in req_cols):
            flash(f"Invalid format. Need: {', '.join(req_cols)}", "error"); return redirect(url_for("tender_items", id=id))
        conn = get_db()
        for index, row in df.iterrows():
            if pd.notna(row['Description']) and str(row['Description']).strip() != "":
                q = float(row['Quantity']) if pd.notna(row['Quantity']) else 0
                s_rate = float(row['Supply Rate']) if pd.notna(row['Supply Rate']) else 0
                e_rate = float(row['Erection Rate']) if pd.notna(row['Erection Rate']) else 0
                total_rate = s_rate + e_rate; amt = round(q * total_rate, 2)
                conn.execute("INSERT INTO tender_items (tender_id, description, unit, quantity, rate, supply_rate, erection_rate, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (id, str(row['Description']).strip(), str(row['Unit']).strip(), q, total_rate, s_rate, e_rate, amt))
        total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id=?", (id,)).fetchone()[0] or 0
        conn.execute("UPDATE tenders SET estimated_value=? WHERE id=?", (total, id))
        conn.commit(); conn.close(); flash("Excel uploaded!", "success")
    except Exception as e: flash(f"Error: {str(e)}", "error")
    return redirect(url_for("tender_items", id=id))

@app.route("/tender/item/edit/<int:item_id>", methods=["POST"])
def edit_tender_item(item_id):
    if not session.get("username"): return redirect(url_for("login"))
    tid = request.form.get("tender_id"); d = request.form.get("description"); u = request.form.get("unit")
    q, s_rate, e_rate = float(request.form.get("quantity") or 0), float(request.form.get("supply_rate") or 0), float(request.form.get("erection_rate") or 0)
    total_rate = s_rate + e_rate; amt = round(q * total_rate, 2)
    conn = get_db()
    conn.execute("UPDATE tender_items SET description=?, unit=?, quantity=?, rate=?, supply_rate=?, erection_rate=?, amount=? WHERE id=?", (d, u, q, total_rate, s_rate, e_rate, amt, item_id))
    total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id=?", (tid,)).fetchone()[0] or 0
    conn.execute("UPDATE tenders SET estimated_value=? WHERE id=?", (total, tid))
    conn.commit(); conn.close(); flash("Item updated!", "success")
    return redirect(url_for("tender_items", id=tid))

@app.route("/tender/sample_excel")
def download_tender_sample():
    if not session.get("username"): return redirect(url_for("login"))
    df = pd.DataFrame({'Description': ['Sample Item'], 'Quantity': [10], 'Unit': ['Nos'], 'Supply Rate': [80], 'Erection Rate': [20]})
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine='openpyxl') as writer: df.to_excel(writer, index=False)
    out.seek(0)
    return send_file(out, download_name="Sample_BOQ.xlsx", as_attachment=True)

@app.route("/tender/update_status/<int:id>/<status>")
def update_tender_status(id, status):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("UPDATE tenders SET status=? WHERE id=?", (status, id)); conn.commit(); conn.close()
    flash(f"Tender marked as {status}!", "success"); return redirect(url_for("tenders"))

@app.route("/tender/convert/<int:id>")
def convert_tender(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); t = conn.execute("SELECT * FROM tenders WHERE id=?", (id,)).fetchone()
    if t and t['status'] == 'Won':
        if not conn.execute("SELECT id FROM parties WHERE party_name=? AND party_type='Debtor'", (t['client_name'],)).fetchone():
            flash(f"Client '{t['client_name']}' not found in Party Master. Create first.", "error")
            conn.close(); return redirect(url_for("parties", new_name=t['client_name']))
        if not conn.execute("SELECT id FROM projects WHERE project_name=?", (t['tender_no'],)).fetchone():
            conn.execute("INSERT INTO projects (project_name, client_name, project_value, status) VALUES (?, ?, ?, 'In Progress')", (t['tender_no'], t['client_name'], t['estimated_value']))
            for item in conn.execute("SELECT * FROM tender_items WHERE tender_id=?", (id,)).fetchall():
                conn.execute("INSERT INTO poq (project_name, material_name, unit, quantity, rate, amount, supply_rate, erection_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (t['tender_no'], item['description'], item['unit'], item['quantity'], item['rate'], item['amount'], item['supply_rate'], item['erection_rate']))
            conn.commit(); flash("Tender converted to Project!", "success")
        else: flash("Project already exists!", "error")
    conn.close(); return redirect(url_for("tenders"))

# ------------------------------------------------------------------
# PURCHASES & PO
# ------------------------------------------------------------------
@app.route("/purchases", methods=["GET", "POST"])
def purchases():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            p_name, s_name, inv = request.form.get("project_name"), request.form.get("supplier_name"), request.form.get("invoice_number")
            if not p_name or not s_name or not inv: flash("Fields required", "error")
            else:
                cur = conn.cursor()
                cur.execute("INSERT INTO purchases (po_number, project_name, supplier_name, invoice_number, invoice_date, subtotal, gst_amount, total_amount) VALUES (?, ?, ?, ?, ?, 0, 0, 0)", (request.form.get("po_number"), p_name, s_name, inv, request.form.get("invoice_date")))
                pid = cur.lastrowid; g_total = 0
                for i in range(len(request.form.getlist("material_name[]"))):
                    mat = request.form.getlist("material_name[]")[i]
                    if mat.strip():
                        q, r, g = float(request.form.getlist("quantity[]")[i] or 0), float(request.form.getlist("rate[]")[i] or 0), float(request.form.getlist("gst_rate[]")[i] or 0)
                        b_amt, g_amt = round(q*r, 2), round(q*r*(g/100), 2)
                        conn.execute("INSERT INTO purchase_items (purchase_id, material_name, description, quantity, rate, gst_rate, amount) VALUES (?, ?, ?, ?, ?, ?, ?)", (pid, mat, request.form.getlist("description[]")[i], q, r, g, b_amt+g_amt))
                        conn.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, 'Receipt', ?, ?, ?, ?)", (mat, request.form.get("invoice_date"), inv, p_name, q, r))
                        g_total += b_amt+g_amt
                conn.execute("UPDATE purchases SET total_amount=? WHERE id=?", (round(g_total, 2), pid))
                conn.commit(); flash("Purchase saved!", "success"); conn.close(); return redirect(url_for("purchases"))
        except Exception as e: flash(f"Error: {str(e)}", "error")
    pl = conn.execute("SELECT * FROM purchases ORDER BY id DESC").fetchall()
    mats = conn.execute("SELECT material_name, unit FROM stock ORDER BY material_name").fetchall()
    po_items = conn.execute("SELECT po.id as po_id, po.project_name, po.vendor_name, po_items.material_name, po_items.quantity, po_items.rate, po_items.unit FROM po JOIN po_items ON po.id=po_items.po_id WHERE po.gm_approval='Approved'").fetchall()
    conn.close(); return render_template("purchases.html", purchases=pl, materials=[dict(r) for r in mats], po_items_list=[dict(r) for r in po_items])

@app.route("/purchases/delete/<int:id>")
def delete_purchase(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM purchase_items WHERE purchase_id=?", (id,)); conn.execute("DELETE FROM purchases WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success"); return redirect(url_for("purchases"))

@app.route("/purchases/edit/<int:id>", methods=["GET", "POST"])
def edit_purchase(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        q, r, g = float(request.form.get("quantity") or 0), float(request.form.get("rate") or 0), float(request.form.get("gst_rate") or 0)
        conn.execute("UPDATE purchases SET project_name=?, supplier_name=?, invoice_number=?, invoice_date=?, material_description=?, quantity=?, rate=?, gst_rate=?, subtotal=?, gst_amount=?, total_amount=? WHERE id=?", (request.form.get("project_name"), request.form.get("supplier_name"), request.form.get("invoice_number"), request.form.get("invoice_date"), request.form.get("material_description"), q, r, g, round(q*r,2), round(q*r*(g/100),2), round(q*r*(1+g/100),2), id))
        conn.commit(); flash("Updated!", "success"); conn.close(); return redirect(url_for("purchases"))
    p = conn.execute("SELECT * FROM purchases WHERE id=?", (id,)).fetchone(); conn.close()
    return render_template("edit_purchase.html", purchase=p)

@app.route("/po", methods=["GET", "POST"])
def po():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            cur = conn.cursor(); cur.execute("INSERT INTO po (project_name, vendor_name, po_date, delivery_address, quotation_no, gm_approval) VALUES (?, ?, ?, ?, ?, 'Pending')", (request.form.get("project_name"), request.form.get("vendor_name"), request.form.get("po_date"), request.form.get("delivery_address"), request.form.get("quotation_no")))
            pid = cur.lastrowid
            for i in range(len(request.form.getlist("material_name[]"))):
                if request.form.getlist("material_name[]")[i].strip():
                    cur.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate) VALUES (?, ?, ?, ?, ?, ?)", (pid, request.form.getlist("material_name[]")[i], request.form.getlist("hsn_code[]")[i], float(request.form.getlist("quantity[]")[i] or 0), request.form.getlist("unit[]")[i], float(request.form.getlist("rate[]")[i] or 0)))
            conn.commit(); flash("PO created!", "success")
        except Exception as e: flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("po"))
    pol = conn.execute("SELECT * FROM po ORDER BY id DESC").fetchall(); pot = []
    for p in pol:
        it = conn.execute("SELECT quantity, rate FROM po_items WHERE po_id=?", (p['id'],)).fetchall()
        d = dict(p); d['total'] = round(sum((i['quantity'] or 0)*(i['rate'] or 0) for i in it)*1.18, 2); pot.append(d)
    pl = conn.execute("SELECT project_name FROM projects").fetchall(); v = conn.execute("SELECT party_name FROM parties WHERE party_type='Creditor'").fetchall(); m = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close(); return render_template("po.html", po_list=pot, project_list=pl, vendors=v, materials=m)

@app.route("/po/edit/<int:id>", methods=["GET", "POST"])
def edit_po(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        conn.execute("UPDATE po SET project_name=?, vendor_name=?, po_date=?, delivery_address=?, quotation_no=? WHERE id=?", (request.form.get("project_name"), request.form.get("vendor_name"), request.form.get("po_date"), request.form.get("delivery_address"), request.form.get("quotation_no"), id))
        conn.execute("DELETE FROM po_items WHERE po_id=?", (id,))
        for i in range(len(request.form.getlist("material_name[]"))):
            if request.form.getlist("material_name[]")[i].strip():
                conn.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate) VALUES (?, ?, ?, ?, ?, ?)", (id, request.form.getlist("material_name[]")[i], request.form.getlist("hsn_code[]")[i], float(request.form.getlist("quantity[]")[i] or 0), request.form.getlist("unit[]")[i], float(request.form.getlist("rate[]")[i] or 0)))
        conn.commit(); flash("PO updated!", "success"); conn.close(); return redirect(url_for("po"))
    pd = conn.execute("SELECT * FROM po WHERE id=?", (id,)).fetchone(); it = conn.execute("SELECT * FROM po_items WHERE po_id=?", (id,)).fetchall()
    pl = conn.execute("SELECT project_name FROM projects").fetchall(); v = conn.execute("SELECT party_name FROM parties WHERE party_type='Creditor'").fetchall(); m = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close(); return render_template("edit_po.html", po=pd, items=it, project_list=pl, vendors=v, materials=m)

@app.route("/po/print/<int:id>")
def print_po(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); p = conn.execute("SELECT * FROM po WHERE id=?", (id,)).fetchone()
    if not p: conn.close(); return redirect(url_for("po"))
    it = conn.execute("SELECT * FROM po_items WHERE po_id=?", (id,)).fetchall(); v = conn.execute("SELECT * FROM parties WHERE party_name=? AND party_type='Creditor'", (p['vendor_name'],)).fetchone()
    conn.close(); st = sum((float(i['quantity'] or 0)*float(i['rate'] or 0)) for i in it); tg = round(st*0.18, 2); intra = True if v and v['gstin'] and v['gstin'].startswith('33') else False
    return render_template("print_po.html", po=p, items=it, vendor=v, sub_total=st, cgst=(tg/2 if intra else 0), sgst=(tg/2 if intra else 0), igst=(0 if intra else tg), total_gst=tg, grand_total=round(st+tg, 2), is_intra_state=intra)

@app.route("/gm_approval")
def gm_approval():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); pp = conn.execute("SELECT * FROM po WHERE gm_approval='Pending' ORDER BY id DESC").fetchall(); ap = conn.execute("SELECT * FROM po WHERE gm_approval='Approved' ORDER BY id DESC").fetchall()
    ppt = []
    for p in pp:
        it = conn.execute("SELECT quantity, rate FROM po_items WHERE po_id=?", (p['id'],)).fetchall()
        d = dict(p); d['total'] = round(sum((i['quantity'] or 0)*(i['rate'] or 0) for i in it)*1.18, 2); ppt.append(d)
    conn.close(); return render_template("gm_approval.html", pending=ppt, approved=ap)

@app.route("/gm_approve/<int:id>")
def gm_approve(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("UPDATE po SET gm_approval='Approved' WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Approved!", "success"); return redirect(url_for("gm_approval"))

@app.route("/md_approval")
def md_approval():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); p = conn.execute("SELECT * FROM purchases WHERE md_approval='Pending' ORDER BY id DESC").fetchall(); a = conn.execute("SELECT * FROM purchases WHERE md_approval='Approved' ORDER BY id DESC").fetchall()
    pwp = []
    for x in p:
        d = dict(x); b = conn.execute("SELECT SUM(amount) FROM poq WHERE project_name=?", (d.get('project_name',''),)).fetchone()[0] or 0
        dn = conn.execute("SELECT SUM((IFNULL(wp.qty_supply,0)*IFNULL(bq.supply_rate,0))+(IFNULL(wp.qty_erection,0)*IFNULL(bq.erection_rate,0))) FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id WHERE wp.project_name=?", (d.get('project_name',''),)).fetchone()[0] or 0
        d['boq_value'] = b; d['done_value'] = dn; d['progress_pct'] = round((dn/b*100) if b>0 else 0, 1); pwp.append(d)
    conn.close(); return render_template("md_approval.html", pending=pwp, approved=a)

@app.route("/md_approve/<int:id>", methods=["POST"])
def md_approve(id):
    if not session.get("username"): return redirect(url_for("login"))
    approved_amt = float(request.form.get("approved_amount") or 0)
    conn = get_db()
    conn.execute("UPDATE purchases SET md_approval='Approved', approved_amount=? WHERE id=?", (approved_amt, id))
    conn.commit(); conn.close()
    flash("Bill Approved successfully!", "success")
    return redirect(url_for("md_approval"))

# ------------------------------------------------------------------
# STOCK & MATERIAL ISSUE
# ------------------------------------------------------------------
@app.route("/stock", methods=["GET", "POST"])
def stock():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        if request.form.get("form_type") == "material":
            conn.execute("INSERT INTO stock (material_code, material_name, unit, opening_stock, reorder_level) VALUES (?, ?, ?, ?, ?)", (request.form.get("material_code"), request.form.get("material_name"), request.form.get("unit"), float(request.form.get("opening_stock") or 0), float(request.form.get("reorder_level") or 0)))
            conn.commit(); flash("Material added!", "success")
        elif request.form.get("form_type") == "ledger":
            conn.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, ?, ?, ?, ?, ?)", (request.form.get("material_name"), request.form.get("transaction_date"), request.form.get("transaction_type"), request.form.get("invoice_no"), request.form.get("project_name"), float(request.form.get("quantity") or 0), float(request.form.get("rate") or 0)))
            conn.commit(); flash("Ledger entry added!", "success")
        conn.close(); return redirect(url_for("stock"))
    mats = conn.execute("SELECT * FROM stock").fetchall()
    summary = []
    for m in mats:
        rec = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt'", (m['material_name'],)).fetchone()[0] or 0
        iss = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Issue'", (m['material_name'],)).fetchone()[0] or 0
        av = m['opening_stock'] + rec - iss
        lr = conn.execute("SELECT rate FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt' ORDER BY id DESC LIMIT 1", (m['material_name'],)).fetchone()
        cr = lr[0] if lr else 0
        summary.append({"id": m['id'], "material_code": m['material_code'], "material_name": m['material_name'], "unit": m['unit'], "opening_stock": m['opening_stock'], "total_receipts": rec, "total_issues": iss, "available_stock": av, "current_rate": cr, "total_value": av*cr, "reorder_level": m['reorder_level']})
    ledger = conn.execute("SELECT * FROM stock_ledger ORDER BY transaction_date ASC, id ASC").fetchall()
    l_list = []; bal = {}
    for r in ledger:
        mn = r['material_name']
        if mn not in bal:
            md = conn.execute("SELECT opening_stock FROM stock WHERE material_name=?", (mn,)).fetchone()
            bal[mn] = md['opening_stock'] if md else 0
        bal[mn] += r['quantity'] if r['transaction_type'] == 'Receipt' else -r['quantity']
        l_list.append({"date": r['transaction_date'], "material": mn, "type": r['transaction_type'], "invoice": r['invoice_no'], "project": r['project_name'], "in_qty": r['quantity'] if r['transaction_type']=='Receipt' else 0, "out_qty": r['quantity'] if r['transaction_type']=='Issue' else 0, "rate": r['rate'], "balance": bal[mn]})
    low = [s for s in summary if s['available_stock'] <= s['reorder_level']]
    pmr = conn.execute("SELECT project_name, material_name, SUM(quantity) as total_issued FROM stock_ledger WHERE transaction_type='Issue' AND project_name != '' GROUP BY project_name, material_name").fetchall()
    pl = conn.execute("SELECT project_name FROM projects").fetchall()
    conn.close(); return render_template("stock.html", summary_list=summary, ledger_list=l_list, low_stock_list=low, project_material_report=pmr, project_list=pl)

@app.route("/stock/delete/<int:id>")
def delete_stock(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); m = conn.execute("SELECT material_name FROM stock WHERE id=?", (id,)).fetchone()
    if m:
        cnt = conn.execute("SELECT COUNT(*) FROM stock_ledger WHERE material_name=?", (m['material_name'],)).fetchone()[0]
        if cnt and request.args.get("force") != "1": flash(f"Has {cnt} entries. Add ?force=1 to delete.", "error")
        else:
            conn.execute("DELETE FROM stock WHERE id=?", (id,)); conn.execute("DELETE FROM stock_ledger WHERE material_name=?", (m['material_name'],)); conn.commit(); flash("Deleted!", "success")
    conn.close(); return redirect(url_for("stock"))

@app.route("/material_issue", methods=["GET", "POST"])
def material_issue():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            proj = request.form.get("project_name"); issue_date = request.form.get("issue_date")
            for i in range(len(request.form.getlist("material_name[]"))):
                mat = request.form.getlist("material_name[]")[i]
                if not mat.strip(): continue
                req_qty = float(request.form.getlist("quantity[]")[i] or 0)
                op = conn.execute("SELECT opening_stock FROM stock WHERE material_name=?", (mat,)).fetchone()
                op_stock = op[0] if op else 0
                rec = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt'", (mat,)).fetchone()[0] or 0
                iss = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Issue'", (mat,)).fetchone()[0] or 0
                avail = op_stock + rec - iss
                if req_qty > avail:
                    flash(f"Stock Error: Only {avail} units of '{mat}' available. Cannot issue {req_qty}.", "error")
                    conn.close(); return redirect(url_for("material_issue"))
            cur = conn.cursor()
            cur.execute("INSERT INTO material_issues (project_name, issue_date, issued_to) VALUES (?, ?, ?)", (proj, issue_date, request.form.get("issued_to")))
            iid = cur.lastrowid; total_expense = 0
            for i in range(len(request.form.getlist("material_name[]"))):
                mat = request.form.getlist("material_name[]")[i]
                if mat.strip():
                    q = float(request.form.getlist("quantity[]")[i] or 0); r = float(request.form.getlist("rate[]")[i] or 0); amt = round(q*r, 2); total_expense += amt
                    cur.execute("INSERT INTO material_issue_items (issue_id, material_name, quantity, rate, amount) VALUES (?, ?, ?, ?, ?)", (iid, mat, q, r, amt))
                    cur.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, 'Issue', ?, ?, ?, ?)", (mat, issue_date, f"MIN-{iid}", proj, q, r))
            if total_expense > 0:
                cur.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', ?, 'Store', 'M')", (issue_date, f"Material Issued (MIN-{iid})", total_expense, proj))
            conn.commit(); flash("Issued successfully!", "success")
        except Exception as e: flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("material_issue"))
    issues = conn.execute("SELECT * FROM material_issues ORDER BY id DESC").fetchall()
    pl = conn.execute("SELECT project_name FROM projects").fetchall()
    mats = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close(); return render_template("material_issue.html", issue_list=issues, project_list=pl, materials=mats)

@app.route("/material_issue/print/<int:id>")
def print_material_issue(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); issue = conn.execute("SELECT * FROM material_issues WHERE id=?", (id,)).fetchone()
    if not issue: flash("Not found!", "error"); conn.close(); return redirect(url_for("material_issue"))
    items = conn.execute("SELECT * FROM material_issue_items WHERE issue_id=?", (id,)).fetchall()
    proj = conn.execute("SELECT * FROM projects WHERE project_name=?", (issue['project_name'],)).fetchone()
    conn.close(); return render_template("print_material_issue.html", issue=issue, items=items, project=proj)

# ------------------------------------------------------------------
# LABOUR
# ------------------------------------------------------------------
@app.route("/labour", methods=["GET", "POST"])
def labour():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        if request.form.get("labour_name"):
            conn.execute("INSERT INTO labour (labour_name, designation, daily_wage, contact_number, join_date, project_name) VALUES (?, ?, ?, ?, ?, ?)", (request.form.get("labour_name"), request.form.get("designation"), float(request.form.get("daily_wage") or 0), request.form.get("contact_number"), request.form.get("join_date"), request.form.get("project_name")))
            conn.commit(); flash("Labour added!", "success"); conn.close(); return redirect(url_for("labour"))
    ll = conn.execute("SELECT * FROM labour ORDER BY id DESC").fetchall()
    pl = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
    conn.close(); return render_template("labour.html", labour_list=ll, project_list=pl)

@app.route("/attendance", methods=["GET", "POST"])
def attendance():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); d = request.args.get("date") or datetime.now().strftime("%Y-%m-%d")
    if request.method == "POST":
        dt = request.form.get("attendance_date"); conn.execute("DELETE FROM labour_attendance WHERE attendance_date=?", (dt,))
        for k, v in request.form.items():
            if k.startswith("status_"):
                lid = k.split("_")[1]
                conn.execute("INSERT INTO labour_attendance (labour_id, attendance_date, status, project_name) VALUES (?, ?, ?, ?)", (lid, dt, v, request.form.get(f"project_{lid}", "")))
        conn.commit(); flash("Attendance saved!", "success"); conn.close(); return redirect(url_for("attendance", date=dt))
    l = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    ea = conn.execute("SELECT * FROM labour_attendance WHERE attendance_date=?", (d,)).fetchall()
    ad = {str(a['labour_id']): a for a in ea}
    conn.close(); return render_template("attendance.html", labours=l, selected_date=d, att_dict=ad)

@app.route("/attendance_report")
def attendance_report():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); m = request.args.get("month") or datetime.now().strftime("%Y-%m")
    l = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    rd = []
    for x in l:
        pd = conn.execute("SELECT COUNT(*) FROM labour_attendance WHERE labour_id=? AND status='Present' AND strftime('%Y-%m', attendance_date)=?", (x['id'], m)).fetchone()[0]
        rd.append({"id": x['id'], "name": x['labour_name'], "designation": x['designation'], "wage": x['daily_wage'], "present_days": pd, "total_salary": pd*x['daily_wage'], "project": x['project_name']})
    conn.close(); return render_template("attendance_report.html", report_data=rd, selected_month=m)

@app.route("/pay_labour_salary", methods=["POST"])
def pay_labour_salary():
    if not session.get("username"): return redirect(url_for("login"))
    month = request.form.get("month"); amount = float(request.form.get("total_amount") or 0)
    if amount > 0:
        conn = get_db()
        conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', 'General', 'Labour Staff', 'Labour')", (datetime.now().strftime("%Y-%m-%d"), f"Labour Salary for {month}", amount))
        conn.commit(); conn.close()
        flash(f"Salary of ₹{amount} for {month} recorded as Expense!", "success")
    return redirect(url_for("attendance_report", month=month))

# ------------------------------------------------------------------
# ACCOUNTS ENTRY & COST CONTROL
# ------------------------------------------------------------------
@app.route("/accounts_entry", methods=["GET", "POST"])
def accounts_entry():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", "") or request.form.get("project_name", "")
    eb_id = request.args.get("edit_bill"); ea_id = request.args.get("edit_account")
    
    if request.method == "POST":
        ft = request.form.get("form_type")
        if ft == "bill":
            try:
                cur = conn.cursor(); desc = request.form.getlist("description[]"); hsn = request.form.getlist("hsn_sac[]"); qty = request.form.getlist("quantity[]"); sr = request.form.getlist("supply_rate[]"); er = request.form.getlist("erection_rate[]"); gst = request.form.getlist("gst_rate[]")
                gt = 0; its = []
                for i in range(len(desc)):
                    if desc[i].strip():
                        q, s, e, g = float(qty[i] or 0), float(sr[i] or 0), float(er[i] or 0), float(gst[i] or 0)
                        b = round(q*(s+e), 2); ga = round(b*(g/100), 2); ta = round(b+ga, 2); gt += ta
                        its.append({"d": desc[i], "h": hsn[i], "q": q, "s": s, "e": e, "r": s+e, "g": g, "b": b, "ga": ga, "ta": ta})
                eid = request.form.get("edit_id")
                if request.form.get("bill_no") and sp and its:
                    if eid:
                        cur.execute("UPDATE bills SET bill_no=?, bill_date=?, total_value=?, bill_type=? WHERE id=?", (request.form.get("bill_no"), request.form.get("bill_date"), round(gt), request.form.get("bill_type"), eid))
                        cur.execute("DELETE FROM bill_items WHERE bill_id=?", (eid,)); bid = eid
                    else:
                        cur.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value, bill_type) VALUES (?, ?, ?, ?, ?)", (sp, request.form.get("bill_no"), request.form.get("bill_date"), round(gt), request.form.get("bill_type"))); bid = cur.lastrowid
                    for it in its:
                        cur.execute("INSERT INTO bill_items (bill_id, description, hsn_sac, quantity, rate, supply_rate, erection_rate, gst_rate, basic_amount, gst_amount, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (bid, it["d"], it["h"], it["q"], it["r"], it["s"], it["e"], it["g"], it["b"], it["ga"], it["ta"]))
                    conn.commit(); flash("Bill saved!", "success")
                else: flash("Required fields missing.", "error")
            except Exception as e: flash(f"Error: {e}", "error")
            conn.close(); return redirect(url_for("accounts_entry", project=sp, tab='tab1'))
            
        elif ft == "ledger":
            try:
                if request.form.get("description"):
                    eid = request.form.get("edit_id")
                    if eid: conn.execute("UPDATE accounts SET transaction_date=?, description=?, amount=?, transaction_type=?, paid_name=?, category=?, bill_no=? WHERE id=?", (request.form.get("transaction_date"), request.form.get("description"), float(request.form.get("amount") or 0), request.form.get("transaction_type"), request.form.get("paid_name"), request.form.get("category"), request.form.get("bill_no"), eid))
                    else: conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category, bill_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (request.form.get("transaction_date"), request.form.get("description"), float(request.form.get("amount") or 0), request.form.get("transaction_type"), sp, request.form.get("paid_name"), request.form.get("category"), request.form.get("bill_no")))
                    conn.commit(); flash("Ledger saved!", "success"); conn.close(); return redirect(url_for("accounts_entry", project=sp, tab='tab2'))
            except Exception as e: flash(f"Error: {e}", "error")
            
    eb_data, eb_items, ea_data = None, [], None
    if eb_id:
        r = conn.execute("SELECT * FROM bills WHERE id=?", (eb_id,)).fetchone()
        if r: eb_data = dict(r); eb_items = [dict(x) for x in conn.execute("SELECT * FROM bill_items WHERE bill_id=?", (eb_id,)).fetchall()]
    if ea_id:
        r = conn.execute("SELECT * FROM accounts WHERE id=?", (ea_id,)).fetchone()
        if r: ea_data = dict(r)
    at = request.args.get("tab", "tab1")
    if ea_id: at = "tab2"
    
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    pa = conn.execute("SELECT party_name FROM parties ORDER BY party_name").fetchall()
    pd, bl, al, ti, te, cb, pb = None, [], [], 0, 0, 0, []
    pending_payments = []
    
    if sp:
        pd = conn.execute("SELECT * FROM projects WHERE project_name=?", (sp,)).fetchone()
        if pd:
            bl = conn.execute("SELECT * FROM bills WHERE project_name=? ORDER BY id DESC", (sp,)).fetchall()
            cb = sum((b['total_value'] or 0) for b in bl)
            al = conn.execute("SELECT * FROM accounts WHERE project_name=? ORDER BY transaction_date DESC, id DESC", (sp,)).fetchall()
            
            ti = sum((r['amount'] or 0) for r in al if r['transaction_type'] in ('Income', 'Debit Note'))
            te = sum((r['amount'] or 0) for r in al if r['transaction_type'] in ('Expense', 'Credit Note'))
            
            pb = conn.execute("SELECT * FROM poq WHERE project_name=?", (sp,)).fetchall()
            pending_payments = conn.execute("SELECT * FROM purchases WHERE project_name = ? AND md_approval = 'Approved' AND payment_status = 'Pending'", (sp,)).fetchall()
            
    conn.close(); 
    return render_template("entry.html", project_list=pl, selected_project=sp, project_details=pd, bills=bl, accounts=al, total_income=ti, total_expense=te, cumulative_bills=cb, parties_list=pa, project_boq_items=pb, edit_bill_data=eb_data, edit_bill_items=eb_items, edit_account_data=ea_data, active_tab=at, pending_payments=pending_payments)

@app.route("/pay_purchase_bill/<int:id>", methods=["POST"])
def pay_purchase_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    bill = conn.execute("SELECT * FROM purchases WHERE id=?", (id,)).fetchone()
    if bill and bill['payment_status'] == 'Pending':
        conn.execute("UPDATE purchases SET payment_status='Paid' WHERE id=?", (id,))
        conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', ?, ?, 'Payment')", (datetime.now().strftime("%Y-%m-%d"), f"Payment for Bill {bill['invoice_number']}", bill['approved_amount'], bill['project_name'], bill['supplier_name']))
        conn.commit(); flash("Payment Successful! Amount deducted from Accounts.", "success")
    else: flash("Invalid or already paid bill.", "error")
    conn.close(); return redirect(url_for("accounts_entry", project=request.args.get("project", ""), tab="tab2"))

@app.route("/accounts/delete/<int:id>")
def delete_account_entry(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM accounts WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success"); return redirect(url_for("accounts_entry", project=request.args.get("project"), tab=request.args.get("tab", "tab4")))

@app.route("/bills/delete/<int:id>")
def delete_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM bill_items WHERE bill_id=?", (id,)); conn.execute("DELETE FROM bills WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success"); return redirect(url_for("accounts_entry", project=request.args.get("project"), tab=request.args.get("tab", "tab3")))

@app.route("/bill/print/<int:id>")
def print_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); b = conn.execute("SELECT * FROM bills WHERE id=?", (id,)).fetchone()
    if not b: flash("Not found!", "error"); conn.close(); return redirect(url_for("accounts"))
    items = conn.execute("SELECT * FROM bill_items WHERE bill_id=?", (id,)).fetchall()
    proj = conn.execute("SELECT * FROM projects WHERE project_name=?", (b['project_name'],)).fetchone()
    cli = conn.execute("SELECT * FROM parties WHERE party_name=? AND party_type='Debtor'", (proj['client_name'],)).fetchone() if proj else None
    conn.close(); et = sum((i['total_amount'] or 0) for i in items); rt = round(et)
    return render_template("print_bill.html", bill=b, items=items, project=proj, client=cli, amount_in_words=num_to_words(rt), rounded_total=rt, round_off=rt-et)

@app.route("/accounts")
def accounts():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); ap = conn.execute("SELECT * FROM projects").fetchall(); pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    pnl = []
    for p in ap:
        pi = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name=? AND transaction_type IN ('Income', 'Debit Note')", (p['project_name'],)).fetchone()[0] or 0
        pe = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name=? AND transaction_type IN ('Expense', 'Credit Note')", (p['project_name'],)).fetchone()[0] or 0
        pnl.append({"id": p['id'], "project_name": p['project_name'], "client": p['client_name'], "value": p['project_value'], "income": pi, "expense": pe, "profit": pi-pe})
    conn.close(); return render_template("accounts.html", pnl_list=pnl, project_list=pl)

@app.route("/project_pnl/<project_name>")
def project_pnl_detail(project_name):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); p = conn.execute("SELECT * FROM projects WHERE project_name=?", (project_name,)).fetchone()
    tx = conn.execute("SELECT * FROM accounts WHERE project_name=? ORDER BY transaction_date ASC, id ASC", (project_name,)).fetchall()
    conn.close(); 
    ti = sum(t['amount'] for t in tx if t['transaction_type'] in ('Income', 'Debit Note'))
    te = sum(t['amount'] for t in tx if t['transaction_type'] in ('Expense', 'Credit Note'))
    return render_template("project_pnl_detail.html", project=p, transactions=tx, total_inflow=ti, total_outflow=te, net_profit=ti-te)

@app.route("/cost_control/<project_name>")
def cost_control(project_name):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE project_name=?", (project_name,)).fetchone()
    boq_items = conn.execute("SELECT * FROM poq WHERE project_name=?", (project_name,)).fetchall()
    
    total_other_exp = conn.execute("""
        SELECT SUM(amount) FROM accounts 
        WHERE project_name=? AND transaction_type = 'Expense' 
        AND IFNULL(category, '') NOT IN ('Payment', 'M', 'Credit Note', 'Debit Note')
    """, (project_name,)).fetchone()[0] or 0
    
    cost_data = []; t_plan=0; t_pur=0; t_fore=0; t_client=0; t_item_profit=0
    
    for item in boq_items:
        item_dict = dict(item)
        qty = item_dict.get('quantity') or 0
        c_sup = item_dict.get('company_supply_rate') or 0
        c_ere = item_dict.get('company_erection_rate') or 0
        
        plan = qty * (c_sup + c_ere)
        
        pur = conn.execute("""
            SELECT SUM(pi.quantity * pi.rate) FROM purchase_items pi 
            JOIN purchases p ON pi.purchase_id = p.id 
            WHERE p.project_name = ? AND LOWER(TRIM(pi.material_name)) = LOWER(TRIM(?))
        """, (project_name, item_dict['material_name'])).fetchone()[0] or 0
        
        done_ere = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id=?", (item_dict['id'],)).fetchone()[0] or 0
        forecast_sup = max(0, (qty * c_sup) - pur)
        forecast_ere = max(0, qty - done_ere) * c_ere
        fore = forecast_sup + forecast_ere
        
        cli_val = qty * ((item_dict.get('supply_rate') or 0) + (item_dict.get('erection_rate') or 0))
        
        item_total_cost = pur + fore
        item_profit = cli_val - item_total_cost
        
        cost_data.append({
            "description": item_dict['material_name'], "qty": qty, "client_value": cli_val, 
            "plan_cost": plan, "actual_pur": pur, "forecast_cost": fore, 
            "total_projected_cost": item_total_cost, "projected_profit": item_profit
        })
        
        t_plan += plan; t_pur += pur; t_fore += fore; t_client += cli_val; t_item_profit += item_profit

    final_net_profit = t_item_profit - total_other_exp
    conn.close()
    
    return render_template("cost_control.html", 
                           project=project, cost_data=cost_data, 
                           total_plan_cost=t_plan, total_actual_pur=t_pur, 
                           total_other_exp=total_other_exp,
                           total_forecast_cost=t_fore, total_client_value=t_client, 
                           total_projected_cost=t_pur+t_fore, 
                           total_item_profit=t_item_profit, 
                           final_net_profit=final_net_profit)

# ------------------------------------------------------------------
# PARTIES & LEDGERS
# ------------------------------------------------------------------
@app.route("/parties", methods=["GET", "POST"])
def parties():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            if request.form.get("party_name") and request.form.get("gstin"):
                if conn.execute("SELECT id FROM parties WHERE party_name=? OR gstin=?", (request.form.get("party_name"), request.form.get("gstin"))).fetchone(): flash("Exists!", "error")
                else:
                    conn.execute("INSERT INTO parties (party_name, party_type, contact_number, email, gstin, address, opening_balance) VALUES (?, ?, ?, ?, ?, ?, ?)", (request.form.get("party_name"), request.form.get("party_type"), request.form.get("contact_number"), request.form.get("email"), request.form.get("gstin"), request.form.get("address"), float(request.form.get("opening_balance") or 0)))
                    conn.commit(); flash("Party created!", "success"); conn.close(); return redirect(url_for("parties"))
            else: flash("Name & GSTIN required.", "error")
        except Exception as e: flash(f"Error: {e}", "error")
    p_list = conn.execute("SELECT * FROM parties ORDER BY id DESC").fetchall(); conn.close()
    return render_template("parties.html", parties=p_list)

@app.route("/parties/delete/<int:id>")
def delete_party(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM parties WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success"); return redirect(url_for("parties"))

@app.route("/parties/edit/<int:id>", methods=["GET", "POST"])
def edit_party(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        if not conn.execute("SELECT id FROM parties WHERE (party_name=? OR gstin=?) AND id!=?", (request.form.get("party_name"), request.form.get("gstin"), id)).fetchone():
            conn.execute("UPDATE parties SET party_name=?, party_type=?, contact_number=?, email=?, gstin=?, address=?, opening_balance=? WHERE id=?", (request.form.get("party_name"), request.form.get("party_type"), request.form.get("contact_number"), request.form.get("email"), request.form.get("gstin"), request.form.get("address"), float(request.form.get("opening_balance") or 0), id))
            conn.commit(); flash("Updated!", "success"); conn.close(); return redirect(url_for("parties"))
        else: flash("Name/GSTIN conflict!", "error")
    p = conn.execute("SELECT * FROM parties WHERE id=?", (id,)).fetchone(); conn.close()
    return render_template("edit_party.html", party=p)

@app.route("/client_ledger")
def client_ledger():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); clients = conn.execute("SELECT DISTINCT paid_name as name FROM accounts WHERE transaction_type='Income' AND paid_name!='' UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type='Debtor' UNION SELECT DISTINCT client_name as name FROM projects").fetchall()
    sc = request.args.get("client", ""); tx = []; ob=0; td=0; tc=0; cb=0
    if sc:
        p = conn.execute("SELECT opening_balance FROM parties WHERE party_name=? AND party_type='Debtor'", (sc,)).fetchone()
        if p: ob = p['opening_balance']
        b = conn.execute("SELECT bill_date as date, 'Bill (Inv: ' || bill_no || ')' as particulars, total_value as debit, 0 as credit FROM bills WHERE project_name IN (SELECT project_name FROM projects WHERE client_name=?)", (sc,)).fetchall()
        pay = conn.execute("SELECT transaction_date as date, 'By ' || description as particulars, 0 as debit, amount as credit FROM accounts WHERE transaction_type IN ('Income', 'Credit Note') AND paid_name=?", (sc,)).fetchall()
        raw = [dict(x) for x in b] + [dict(x) for x in pay]; raw.sort(key=lambda x: x['date'] if x['date'] else '9999')
        rb = ob; td = ob; tc = 0
        for r in raw:
            d = r['debit'] or 0; c = r['credit'] or 0; td += d; tc += c; rb += d-c; r['balance'] = rb; tx.append(r)
        cb = rb
    conn.close(); return render_template("client_ledger.html", clients=clients, transactions=tx, selected_client=sc, opening_balance=ob, total_debit=td, total_credit=tc, closing_balance=cb)

@app.route("/vendor_ledger")
def vendor_ledger():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); v = conn.execute("SELECT DISTINCT supplier_name as name FROM purchases UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type='Creditor'").fetchall()
    sv = request.args.get("vendor", ""); tx = []; ob=0; tpo=0; tb=0; tp=0; cb=0
    if sv:
        p = conn.execute("SELECT opening_balance FROM parties WHERE party_name=? AND party_type='Creditor'", (sv,)).fetchone()
        if p: ob = p['opening_balance']
        po = conn.execute("SELECT po.id, po.po_date as date, 'PO #' || po.id as particulars, 'PO' as type, IFNULL(SUM(po_items.quantity*po_items.rate),0)*1.18 as po_value, 0 as bill_value, 0 as paid_amount FROM po JOIN po_items ON po.id=po_items.po_id WHERE po.vendor_name=? GROUP BY po.id", (sv,)).fetchall()
        b = conn.execute("SELECT id, invoice_date as date, 'Bill' as particulars, 'Bill' as type, 0 as po_value, total_amount as bill_value, 0 as paid_amount FROM purchases WHERE supplier_name=?", (sv,)).fetchall()
        pay = conn.execute("SELECT id, transaction_date as date, 'Payment' as particulars, 'Payment' as type, 0 as po_value, 0 as bill_value, amount as paid_amount FROM accounts WHERE transaction_type IN ('Expense', 'Debit Note') AND paid_name=?", (sv,)).fetchall()
        raw = [dict(x) for x in po] + [dict(x) for x in b] + [dict(x) for x in pay]; raw.sort(key=lambda x: x['date'] if x['date'] else '9999')
        rb = ob
        for r in raw:
            if r['type'] != 'PO': rb += (r['bill_value'] or 0) - (r['paid_amount'] or 0)
            r['balance'] = rb
            if r['type']=='PO': tpo += r['po_value'] or 0
            elif r['type']=='Bill': tb += r['bill_value'] or 0
            elif r['type']=='Payment': tp += r['paid_amount'] or 0
            tx.append(r)
        cb = rb
    conn.close(); return render_template("vendor_ledger.html", vendors=v, transactions=tx, selected_vendor=sv, opening_balance=ob, total_po_value=tpo, total_bill_value=tb, total_paid=tp, closing_balance=cb, po_bill_diff=tpo-tb)

# ------------------------------------------------------------------
# BOQ & WORK PROGRESS
# ------------------------------------------------------------------
@app.route("/poq", methods=["GET", "POST"])
def poq():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", ""); eid = request.args.get("edit")
    if request.method == "POST":
        sp = request.form.get("project_name", ""); eid = request.form.get("edit_id")
        try:
            cur = conn.cursor(); desc = request.form.getlist("item_description[]"); units = request.form.getlist("unit[]"); qtys = request.form.getlist("quantity[]"); srs = request.form.getlist("supply_rate[]"); ers = request.form.getlist("erection_rate[]"); csrs = request.form.getlist("comp_supply_rate[]"); cers = request.form.getlist("comp_erection_rate[]"); subs = request.form.getlist("subcon_name[]"); subrs = request.form.getlist("subcon_rate[]")
            for i in range(len(desc)):
                if desc[i].strip():
                    q, sr, er, csr, cer = float(qtys[i] or 0), float(srs[i] or 0), float(ers[i] or 0), float(csrs[i] or 0), float(cers[i] or 0)
                    sn = subs[i].strip() if i < len(subs) and subs[i] else ""; scr = float(subrs[i] or 0)
                    u = units[i]; tr = sr + er; amt = round(q*tr, 2)
                    if eid:
                        cur.execute("UPDATE poq SET material_name=?, unit=?, quantity=?, rate=?, amount=?, supply_rate=?, erection_rate=?, company_supply_rate=?, company_erection_rate=?, subcon_name=?, subcon_rate=? WHERE id=?", (desc[i], u, q, tr, amt, sr, er, csr, cer, sn, scr, eid))
                        flash("Updated!", "success"); eid = None
                    else:
                        cur.execute("INSERT INTO poq (project_name, material_name, unit, quantity, rate, amount, supply_rate, erection_rate, company_supply_rate, company_erection_rate, subcon_name, subcon_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (sp, desc[i], u, q, tr, amt, sr, er, csr, cer, sn, scr))
                        if not cur.execute("SELECT id FROM stock WHERE material_name=?", (desc[i],)).fetchone(): cur.execute("INSERT INTO stock (material_name, unit, opening_stock) VALUES (?, ?, 0)", (desc[i], u))
            conn.commit(); flash("Saved!", "success")
        except Exception as e: flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("poq", project=sp))
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall(); bl = []; tb=0; ebd = None
    if eid: ebd = conn.execute("SELECT * FROM poq WHERE id=?", (eid,)).fetchone()
    if sp:
        bl = conn.execute("SELECT * FROM poq WHERE project_name=? ORDER BY id ASC", (sp,)).fetchall(); tb = sum((x['amount'] or 0) for x in bl)
    conn.close(); return render_template("poq.html", project_list=pl, selected_project=sp, boq_list=bl, total_boq_value=tb, edit_boq_data=ebd)

@app.route("/poq/delete/<int:id>")
def delete_poq(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM poq WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success"); return redirect(url_for("poq", project=request.args.get("project", "")))

@app.route("/work_progress", methods=["GET", "POST"])
def work_progress():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", "")
    if request.method == "POST":
        bid = request.form.get("boq_item_id"); qs = float(request.form.get("qty_supply") or 0); qe = float(request.form.get("qty_erection") or 0)
        if bid and (qs > 0 or qe > 0):
            conn.execute("INSERT INTO work_progress (project_name, boq_item_id, work_date, qty_supply, qty_erection, remarks) VALUES (?, ?, ?, ?, ?, ?)", (sp, bid, request.form.get("work_date"), qs, qe, request.form.get("remarks", "")))
            conn.commit(); flash("Updated!", "success")
        conn.close(); return redirect(url_for("work_progress", project=sp))
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall(); bpl = []; wh = []
    if sp:
        for i in conn.execute("SELECT * FROM poq WHERE project_name=? ORDER BY id ASC", (sp,)).fetchall():
            ds = conn.execute("SELECT SUM(qty_supply) FROM work_progress WHERE boq_item_id=?", (i['id'],)).fetchone()[0] or 0
            de = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id=?", (i['id'],)).fetchone()[0] or 0
            bpl.append({"id": i['id'], "description": i['material_name'], "unit": i['unit'], "total_qty": i['quantity'] or 0, "done_supply": ds, "done_erection": de, "balance_supply": (i['quantity'] or 0)-ds, "balance_erection": (i['quantity'] or 0)-de, "supply_rate": i['supply_rate'] or 0, "erection_rate": i['erection_rate'] or 0})
        wh = [dict(r) for r in conn.execute("SELECT wp.id, wp.work_date, bq.material_name, wp.qty_supply, wp.qty_erection, wp.remarks, wp.is_billed_supply, wp.is_billed_erection FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id WHERE wp.project_name=? ORDER BY wp.work_date DESC, wp.id DESC", (sp,)).fetchall()]
    conn.close(); return render_template("work_progress.html", project_list=pl, selected_project=sp, boq_progress_list=bpl, work_history=wh)

@app.route("/work_progress/delete/<int:id>")
def delete_work_progress(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); wp = conn.execute("SELECT * FROM work_progress WHERE id=?", (id,)).fetchone()
    if wp:
        if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1: flash("Cannot delete billed work.", "error")
        else: conn.execute("DELETE FROM work_progress WHERE id=?", (id,)); conn.commit(); flash("Deleted!", "success")
    conn.close(); return redirect(url_for("work_progress", project=request.args.get("project", "")))

@app.route("/work_progress/edit/<int:id>", methods=["GET", "POST"])
def edit_work_progress(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); wp = conn.execute("SELECT * FROM work_progress WHERE id=?", (id,)).fetchone()
    if not wp: flash("Not found!", "error"); conn.close(); return redirect(url_for("work_progress"))
    if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1: flash("Cannot edit billed work.", "error"); conn.close(); return redirect(url_for("work_progress", project=wp['project_name']))
    if request.method == "POST":
        conn.execute("UPDATE work_progress SET work_date=?, qty_supply=?, qty_erection=?, remarks=? WHERE id=?", (request.form.get("work_date"), float(request.form.get("qty_supply") or 0), float(request.form.get("qty_erection") or 0), request.form.get("remarks"), id))
        conn.commit(); conn.close(); flash("Updated!", "success"); return redirect(url_for("work_progress", project=wp['project_name']))
    bq = conn.execute("SELECT * FROM poq WHERE id=?", (wp['boq_item_id'],)).fetchone(); conn.close()
    return render_template("edit_work_progress.html", wp=wp, boq_item=bq)

@app.route("/generate_ra_bill/<project_name>")
def generate_ra_bill(project_name):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    try:
        cur = conn.cursor(); today = datetime.now().strftime("%Y-%m-%d")
        us = conn.execute("SELECT wp.id, bq.material_name, bq.supply_rate, wp.qty_supply FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id WHERE wp.project_name=? AND wp.is_billed_supply=0 AND wp.qty_supply>0", (project_name,)).fetchall()
        if us:
            b_no = f"RA-SUP-{project_name[:3].upper()}-{datetime.now().strftime('%m%d%H%M')}"; tot_val = 0; items = []
            for w in us:
                basic = w['qty_supply'] * w['supply_rate']; gst = round(basic * 0.18, 2); tot = round(basic + gst, 2); tot_val += tot
                items.append((w['id'], w['material_name'], w['qty_supply'], w['supply_rate'], basic, gst, tot))
            cur.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value) VALUES (?, ?, ?, ?)", (project_name, b_no, today, round(tot_val))); b_id = cur.lastrowid
            for i in items:
                cur.execute("INSERT INTO bill_items (bill_id, description, quantity, rate, supply_rate, erection_rate, gst_rate, basic_amount, gst_amount, total_amount) VALUES (?, ?, ?, ?, ?, 0, 18, ?, ?, ?)", (b_id, f"[Supply] {i[1]}", i[2], i[3], i[3], i[4], i[5], i[6]))
                cur.execute("UPDATE work_progress SET is_billed_supply=1 WHERE id=?", (i[0],))
            flash(f"Supply Bill {b_no} generated with GST: ₹{tot_val:.2f}", "success")
        ue = conn.execute("SELECT wp.id, bq.material_name, bq.erection_rate, wp.qty_erection FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id WHERE wp.project_name=? AND wp.is_billed_erection=0 AND wp.qty_erection>0", (project_name,)).fetchall()
        if ue:
            b_no = f"RA-ERE-{project_name[:3].upper()}-{datetime.now().strftime('%m%d%H%M')}"; tot_val = 0; items = []
            for w in ue:
                basic = w['qty_erection'] * w['erection_rate']; gst = round(basic * 0.18, 2); tot = round(basic + gst, 2); tot_val += tot
                items.append((w['id'], w['material_name'], w['qty_erection'], w['erection_rate'], basic, gst, tot))
            cur.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value) VALUES (?, ?, ?, ?)", (project_name, b_no, today, round(tot_val))); b_id = cur.lastrowid
            for i in items:
                cur.execute("INSERT INTO bill_items (bill_id, description, quantity, rate, supply_rate, erection_rate, gst_rate, basic_amount, gst_amount, total_amount) VALUES (?, ?, ?, ?, 0, ?, 18, ?, ?, ?)", (b_id, f"[Erection] {i[1]}", i[2], i[3], i[3], i[4], i[5], i[6]))
                cur.execute("UPDATE work_progress SET is_billed_erection=1 WHERE id=?", (i[0],))
            flash(f"Erection Bill {b_no} generated with GST: ₹{tot_val:.2f}", "success")
        if not us and not ue: flash("No unbilled work found.", "error")
        conn.commit()
    except Exception as e: flash(f"Error: {e}", "error")
    conn.close(); return redirect(url_for("accounts_entry", project=project_name))

# ------------------------------------------------------------------
# REPORTS & GST
# ------------------------------------------------------------------
@app.route("/gst_reconciliation", methods=["GET", "POST"])
def gst_reconciliation():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        f = request.files.get('file')
        if f:
            conn.execute("DELETE FROM gstr2b_data")
            try:
                df = pd.read_excel(f)
                if not {'Invoice Number', 'Trade/Legal Name', 'Total'}.issubset(df.columns): flash("Invalid Excel Columns!", "error")
                else:
                    for _, r in df.iterrows():
                        conn.execute("INSERT INTO gstr2b_data (supplier_name, invoice_number, total_value) VALUES (?, ?, ?)", (str(r.get('Trade/Legal Name')), str(r.get('Invoice Number')), float(r.get('Total', 0))))
                    conn.commit(); flash("Uploaded! Click Reconcile.", "success")
            except Exception as e: flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("gst_reconciliation"))
    ud = conn.execute("SELECT * FROM gstr2b_data ORDER BY id DESC").fetchall(); conn.close()
    return render_template("gst_reconciliation.html", uploaded_data=ud)

@app.route("/run_reconciliation")
def run_reconciliation():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    for row in conn.execute("SELECT * FROM gstr2b_data").fetchall():
        p = conn.execute("SELECT total_amount FROM purchases WHERE invoice_number=?", (row['invoice_number'],)).fetchone()
        if p:
            if abs((p['total_amount'] or 0)-(row['total_value'] or 0)) < 0.01: conn.execute("UPDATE gstr2b_data SET match_status='Matched' WHERE id=?", (row['id'],))
            else: conn.execute("UPDATE gstr2b_data SET match_status='Amount Mismatch' WHERE id=?", (row['id'],))
        else: conn.execute("UPDATE gstr2b_data SET match_status='Missing' WHERE id=?", (row['id'],))
    conn.commit(); conn.close(); flash("Reconciled!", "success"); return redirect(url_for("gst_reconciliation"))

@app.route("/reports")
def reports():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", ""); sm = request.args.get("month", "")
    p = conn.execute("SELECT * FROM projects" + (" WHERE project_name=?" if sp else ""), ((sp,) if sp else ())).fetchall()
    tov = sum((x['project_value'] or 0) for x in p)
    pq = "SELECT * FROM purchases WHERE 1=1"; pp = []
    if sp: pq += " AND project_name=?"; pp.append(sp)
    if sm: pq += " AND strftime('%Y-%m', invoice_date)=?"; pp.append(sm)
    pl = conn.execute(pq, pp).fetchall(); tpv = sum(x['total_amount'] for x in pl)
    bq = "SELECT * FROM bills WHERE 1=1"; bp = []
    if sp: bq += " AND project_name=?"; bp.append(sp)
    if sm: bq += " AND strftime('%Y-%m', bill_date)=?"; bp.append(sm)
    bl = conn.execute(bq, bp).fetchall(); tsv = sum(x['total_value'] for x in bl)
    proj_l = conn.execute("SELECT project_name FROM projects").fetchall(); conn.close()
    return render_template("reports.html", projects=p, purchase_list=pl, bills_list=bl, project_list=proj_l, selected_project=sp, selected_month=sm, total_order_value=tov, total_purchase_value=tpv, total_sales_value=tsv)

@app.route("/reports/export/csv")
def reports_export_csv():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor": return redirect(url_for("dashboard"))
    conn = get_db(); sp = request.args.get("project", ""); sm = request.args.get("month", "")
    pq = "SELECT * FROM purchases WHERE 1=1"; pp = []
    if sp: pq += " AND project_name=?"; pp.append(sp)
    if sm: pq += " AND strftime('%Y-%m', invoice_date)=?"; pp.append(sm)
    pl = conn.execute(pq, pp).fetchall()
    bq = "SELECT * FROM bills WHERE 1=1"; bp = []
    if sp: bq += " AND project_name=?"; bp.append(sp)
    if sm: bq += " AND strftime('%Y-%m', bill_date)=?"; bp.append(sm)
    bl = conn.execute(bq, bp).fetchall(); conn.close()
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["PURCHASES"]); w.writerow(["Date", "Invoice", "Project", "Vendor", "Amount"]); tp = 0
    for x in pl: tp += x['total_amount'] or 0; w.writerow([x['invoice_date'], x['invoice_number'], x['project_name'], x['supplier_name'], f"{x['total_amount']:.2f}"])
    w.writerow(["", "", "", "TOTAL", f"{tp:.2f}"]); w.writerow([]); w.writerow(["SALES"]); w.writerow(["Date", "Bill", "Project", "Amount"]); tb = 0
    for x in bl: tb += x['total_value'] or 0; w.writerow([x['bill_date'], x['bill_no'], x['project_name'], f"{x['total_value']:.2f}"])
    w.writerow(["", "", "TOTAL", f"{tb:.2f}"]); out.seek(0)
    return send_file(io.BytesIO(out.getvalue().encode("utf-8-sig")), mimetype="text/csv", as_attachment=True, download_name=f"Report_{datetime.now().strftime('%Y%m%d')}.csv")

@app.route("/vendor_report")
def vendor_report():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", ""); pairs = []
    if sp: pairs = conn.execute("SELECT DISTINCT project_name, vendor_name FROM po WHERE project_name=? UNION SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases WHERE project_name=?", (sp, sp)).fetchall()
    else: pairs = conn.execute("SELECT DISTINCT project_name, vendor_name FROM po UNION SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases").fetchall()
    tpv = conn.execute("SELECT SUM(project_value) FROM projects" + (" WHERE project_name=?" if sp else ""), ((sp,) if sp else ())).fetchone()[0] or 0
    rd = []; gpo=0; gpu=0; gpa=0; gdi=0; gpy=0
    for p in pairs:
        po = conn.execute("SELECT SUM(po_items.quantity*po_items.rate*1.18) FROM po JOIN po_items ON po.id=po_items.po_id WHERE po.project_name=? AND po.vendor_name=?", (p['project_name'], p['vendor_name'])).fetchone()[0] or 0
        pu = conn.execute("SELECT SUM(total_amount) FROM purchases WHERE project_name=? AND supplier_name=?", (p['project_name'], p['vendor_name'])).fetchone()[0] or 0
        pa = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name=? AND transaction_type IN ('Expense', 'Debit Note') AND paid_name=?", (p['project_name'], p['vendor_name'])).fetchone()[0] or 0
        rd.append({"project": p['project_name'], "vendor": p['vendor_name'], "po": po, "purchase": pu, "paid": pa, "diff": po-pu, "balance_payable": pu-pa})
        gpo += po; gpu += pu; gpa += pa; gdi += (po-pu); gpy += (pu-pa)
    pl = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall(); conn.close()
    return render_template("vendor_report.html", report_data=rd, project_list=pl, selected_project=sp, total_proj_val_gst=round(tpv*1.18, 2), pl_amount=round(tpv*1.18, 2)-gpo, grand_po=gpo, grand_purchase=gpu, grand_paid=gpa, grand_diff=gdi, grand_payable=gpy)

@app.route("/backup")
def backup():
    if not session.get("username"): return redirect(url_for("login"))
    if os.path.exists(DATABASE): return send_file(DATABASE, as_attachment=True, download_name=f"Backup_{datetime.now().strftime('%Y%m%d')}.db")
    flash("DB not found!", "error"); return redirect(url_for("dashboard"))

@app.route("/search")
def search():
    if not session.get("username"): return redirect(url_for("login"))
    query = request.args.get("q", "").strip()
    if not query: return redirect(url_for("dashboard"))
    conn = get_db(); term = f"%{query}%"
    projects = conn.execute("SELECT * FROM projects WHERE project_name LIKE ? OR client_name LIKE ?", (term, term)).fetchall()
    purchases = conn.execute("SELECT DISTINCT p.* FROM purchases p LEFT JOIN purchase_items pi ON p.id=pi.purchase_id WHERE p.invoice_number LIKE ? OR p.supplier_name LIKE ? OR pi.material_name LIKE ?", (term, term, term)).fetchall()
    pos = conn.execute("SELECT * FROM po WHERE vendor_name LIKE ? OR quotation_no LIKE ? OR project_name LIKE ?", (term, term, term)).fetchall()
    parties = conn.execute("SELECT * FROM parties WHERE party_name LIKE ? OR gstin LIKE ?", (term, term)).fetchall()
    bills = conn.execute("SELECT DISTINCT b.* FROM bills b LEFT JOIN bill_items bi ON b.id=bi.bill_id WHERE b.bill_no LIKE ? OR b.project_name LIKE ? OR bi.description LIKE ?", (term, term, term)).fetchall()
    accounts = conn.execute("SELECT * FROM accounts WHERE description LIKE ? OR paid_name LIKE ?", (term, term)).fetchall()
    labours = conn.execute("SELECT * FROM labour WHERE labour_name LIKE ? OR designation LIKE ?", (term, term)).fetchall()
    conn.close()
    return render_template("search_results.html", query=query, projects=projects, purchases=purchases, pos=pos, parties=parties, bills=bills, accounts=accounts, labours=labours)

# ------------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    print("--------------------------------")
    print("GOMS ELECTRICALS PVT LTD ERP")
    print("--------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)