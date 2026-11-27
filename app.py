from flask_wtf.csrf import CSRFProtect
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
import random
import smtplib
import calendar
from email.message import EmailMessage
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "goms_erp_new.db")

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-fallback-key-change-me')
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
csrf = CSRFProtect(app)

# ================= SECURITY CONFIGURATIONS =================
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("HTTPS_MODE", "0") == "1"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(minutes=15)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "goms-local-development-key-change-before-deployment")
csrf = CSRFProtect(app)

if not os.environ.get("FLASK_SECRET_KEY"):
    print("WARNING: Using default Flask secret key. Set FLASK_SECRET_KEY before deploying!")

@app.context_processor
def inject_permissions():
    role = session.get('role', 'Admin')
    return dict(is_admin_or_gm=role in ['MD', 'Admin', 'GM'])

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ================= TEMPLATE FILTERS =================
@app.template_filter('dateformat')
def dateformat(value, format='%d/%m/%Y'):
    if not value: return "-"
    try: return datetime.strptime(value, '%Y-%m-%d').strftime(format)
    except: return value

@app.template_filter('inr')
def format_inr(number):
    if number is None: return "0"
    try: number = float(number)
    except: return "0"
    is_negative = False
    if number < 0:
        is_negative = True
        number = abs(number)
    integer_part = str(round(number))
    if len(integer_part) > 3:
        last_three = integer_part[-3:]
        remaining = integer_part[:-3]
        groups = []
        while len(remaining) > 2:
            groups.insert(0, remaining[-2:])
            remaining = remaining[:-2]
        if remaining: groups.insert(0, remaining)
        formatted_integer = ",".join(groups) + "," + last_three
    else:
        formatted_integer = integer_part
    result = formatted_integer
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

# ================= AUTH HELPERS & DB =================
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

def log_activity(action, details=""):
    try:
        conn = get_db()
        conn.execute("INSERT INTO activity_logs (username, action, details, timestamp) VALUES (?, ?, ?, ?)",
                     (session.get("username", "System"), action, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Log Error:", e)

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
    conn.execute("CREATE TABLE IF NOT EXISTS indents (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, indent_date TEXT, requested_by TEXT, status TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS indent_items (id INTEGER PRIMARY KEY AUTOINCREMENT, indent_id INTEGER NOT NULL, material_name TEXT NOT NULL, quantity REAL DEFAULT 0, remarks TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS vendor_quotes (id INTEGER PRIMARY KEY AUTOINCREMENT, indent_id INTEGER NOT NULL, vendor_name TEXT NOT NULL, quote_date TEXT, delivery_days INTEGER DEFAULT 0, payment_terms TEXT, technical_remarks TEXT, status TEXT DEFAULT 'Pending', total_amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS quote_items (id INTEGER PRIMARY KEY AUTOINCREMENT, quote_id INTEGER NOT NULL, indent_item_id INTEGER NOT NULL, material_name TEXT, rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS subcon_bills (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, subcon_name TEXT NOT NULL, bill_date TEXT, total_amount REAL DEFAULT 0, remarks TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS subcon_bill_items (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL, boq_item_id INTEGER NOT NULL, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS stock_adjustments (id INTEGER PRIMARY KEY AUTOINCREMENT, adjustment_date TEXT, material_name TEXT, quantity REAL DEFAULT 0, reason TEXT, remarks TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS project_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, doc_name TEXT NOT NULL, file_name TEXT NOT NULL, upload_date TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, details TEXT, timestamp TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_code TEXT UNIQUE, name TEXT NOT NULL, designation TEXT, department TEXT, join_date TEXT, phone TEXT, email TEXT, basic_salary REAL DEFAULT 0, is_active INTEGER DEFAULT 1)")
    conn.execute("CREATE TABLE IF NOT EXISTS staff_advances (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_id INTEGER NOT NULL, date TEXT, amount REAL, reason TEXT, status TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS staff_leaves (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_id INTEGER NOT NULL, start_date TEXT, end_date TEXT, leave_type TEXT, reason TEXT, status TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS staff_attendance (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_id INTEGER NOT NULL, attendance_date TEXT, status TEXT, in_time TEXT, out_time TEXT)")
    conn.execute("""CREATE TABLE IF NOT EXISTS credit_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL, project_name TEXT NOT NULL, cn_no TEXT NOT NULL, cn_date TEXT, total_value REAL DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS credit_note_items (id INTEGER PRIMARY KEY AUTOINCREMENT, cn_id INTEGER NOT NULL, description TEXT NOT NULL, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, basic_amount REAL DEFAULT 0, gst_amount REAL DEFAULT 0, total_amount REAL DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY AUTOINCREMENT, lead_date TEXT, client_name TEXT, contact_person TEXT, phone TEXT, project_name TEXT, location TEXT, estimated_value REAL DEFAULT 0, source TEXT, status TEXT DEFAULT 'New', next_followup TEXT, remarks TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS employee_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_id INTEGER NOT NULL, doc_name TEXT NOT NULL, file_name TEXT NOT NULL, upload_date TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS payroll (id INTEGER PRIMARY KEY AUTOINCREMENT, emp_id INTEGER NOT NULL, month TEXT NOT NULL, basic_salary REAL DEFAULT 0, earned_gross REAL DEFAULT 0, present_days REAL DEFAULT 0, advance_deducted REAL DEFAULT 0, pf_deducted REAL DEFAULT 0, tds_deducted REAL DEFAULT 0, net_salary REAL DEFAULT 0, payment_date TEXT)""")
    conn.commit()

    def add_column(table, column, col_type):
        try:
            cursor = conn.execute(f"PRAGMA table_info({table})")
            if column not in [info[1] for info in cursor.fetchall()]:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                conn.commit()
        except: pass

    add_column("purchases", "md_approval", "TEXT DEFAULT 'Pending'")
    add_column("purchases", "approved_amount", "REAL DEFAULT 0")
    add_column("purchases", "payment_status", "TEXT DEFAULT 'Pending'")
    add_column("purchases", "tds_percent", "REAL DEFAULT 0")
    add_column("purchases", "retention_percent", "REAL DEFAULT 0")
    add_column("purchases", "net_payable", "REAL DEFAULT 0")
    add_column("purchase_items", "po_item_id", "INTEGER")
    add_column("users", "role", "TEXT DEFAULT 'Admin'")
    add_column("poq", "unit", "TEXT")
    add_column("poq", "rate", "REAL")
    add_column("poq", "amount", "REAL")
    add_column("poq", "actual_quantity", "REAL DEFAULT 0")
    add_column("po_items", "unit", "TEXT")
    add_column("po_items", "gst_rate", "REAL DEFAULT 18")
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
    add_column("bill_items", "claim_percentage", "REAL DEFAULT 100")
    add_column("po", "gm_approval", "TEXT DEFAULT 'Pending'")
    add_column("accounts", "bill_no", "TEXT")
    add_column("tender_items", "supply_rate", "REAL DEFAULT 0")
    add_column("tender_items", "erection_rate", "REAL DEFAULT 0")
    add_column("tender_items", "company_supply_rate", "REAL DEFAULT 0")
    add_column("tender_items", "company_erection_rate", "REAL DEFAULT 0")
    add_column("work_progress", "billed_qty_supply", "REAL DEFAULT 0")
    add_column("work_progress", "billed_qty_erection", "REAL DEFAULT 0")
    add_column("parties", "is_blocked", "INTEGER DEFAULT 0")
    add_column("vendor_quotes", "brand_name", "TEXT")
    add_column("subcon_bills", "material_deduction", "REAL DEFAULT 0")
    add_column("employees", "hra", "REAL DEFAULT 0")
    add_column("employees", "allowances", "REAL DEFAULT 0")
    add_column("employees", "pf_amount", "REAL DEFAULT 0")
    add_column("employees", "tds_percent", "REAL DEFAULT 0")
    add_column("payroll", "earned_gross", "REAL DEFAULT 0")
    add_column("payroll", "pf_deducted", "REAL DEFAULT 0")
    add_column("payroll", "tds_deducted", "REAL DEFAULT 0")

    indexes = ["CREATE INDEX IF NOT EXISTS idx_purchases_project ON purchases(project_name)", "CREATE INDEX IF NOT EXISTS idx_bills_project ON bills(project_name)", "CREATE INDEX IF NOT EXISTS idx_accounts_project ON accounts(project_name)", "CREATE INDEX IF NOT EXISTS idx_poq_project ON poq(project_name)", "CREATE INDEX IF NOT EXISTS idx_wp_project ON work_progress(project_name)"]
    for idx in indexes:
        try: conn.execute(idx)
        except: pass
    conn.commit()

    # Create default MD user if no users exist
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        salt, pw = hash_password("ChangeMe@123")
        conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES ('admin', ?, ?, 'MD')", (salt, pw))
        conn.commit()
    else:
        # One-time migration: if no MD exists, promote first Admin to MD
        md_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='MD'").fetchone()[0]
        if md_count == 0:
            first_admin = conn.execute("SELECT id FROM users WHERE role='Admin' LIMIT 1").fetchone()
            if first_admin:
                conn.execute("UPDATE users SET role='MD' WHERE id=?", (first_admin['id'],))
                conn.commit()
    conn.close()

@app.before_request
def restrict_access():
    if not session.get("username"): return
    role = session.get("role", "MD")
    endpoint = request.endpoint

    finance_routes = ['accounts', 'accounts_entry', 'delete_account_entry', 'delete_bill',
                      'print_bill', 'client_ledger', 'vendor_ledger', 'gst_reconciliation',
                      'run_reconciliation', 'gstr1', 'credit_notes', 'delete_credit_note',
                      'general_expenses', 'company_pnl', 'pay_purchase_bill', 'payroll']
    if endpoint in finance_routes and role not in ['MD', 'GM', 'Accountant']:
        flash("Access Denied: Finance module is restricted.", "error")
        return redirect(url_for('dashboard'))

    if role == "MD": return

    party_routes = ['parties', 'edit_party', 'delete_party', 'toggle_block_party']
    if endpoint in party_routes and role not in ['MD', 'GM', 'Accountant']:
        flash("Access Denied: Only MD, GM and Accountants can manage Parties.", "error")
        return redirect(url_for('dashboard'))

    procurement_routes = ['po', 'edit_po', 'print_po', 'gm_approval', 'gm_approve',
                          'purchases', 'edit_purchase', 'delete_purchase', 'md_approval',
                          'md_approve', 'vendor_report', 'quote_comparison', 'approve_quote',
                          'generate_po_from_quote', 'indent_quotes']
    if endpoint in procurement_routes and role not in ['GM', 'Store Keeper']:
        flash("Access Denied: Procurement is restricted.", "error")
        return redirect(url_for('dashboard'))

    admin_routes = ['users', 'delete_user', 'edit_user_role', 'activity_log', 'backup', 'bulk_import']
    if endpoint in admin_routes and role not in ['GM']:
        flash("Access Denied: Only MD can manage System settings.", "error")
        return redirect(url_for('dashboard'))

    if role == "Site Supervisor":
        blocked_for_site = ['parties', 'edit_party', 'delete_party', 'projects', 'edit_project',
                            'delete_project', 'poq', 'delete_poq', 'employees', 'staff_advances',
                            'leave_management', 'leave_approve', 'tenders', 'tender_items',
                            'convert_tender', 'update_tender_status', 'leads', 'subcon']
        if endpoint in blocked_for_site:
            flash("Access Denied: You don't have permission for this page.", "error")
            return redirect(url_for('dashboard'))

    if role == "Store Keeper":
        blocked_for_store = ['employees', 'staff_advances', 'leave_management', 'labour',
                             'attendance', 'attendance_report', 'subcon']
        if endpoint in blocked_for_store:
            flash("Access Denied: Store Keepers cannot access HR/Payroll.", "error")
            return redirect(url_for('dashboard'))

# ==========================================
# EMAIL OTP SENDER FUNCTION
# ==========================================
def send_otp_email(receiver_email, otp_code):
    sender_email = "thileepanas@gmail.com"
    app_password = "xxxx xxxx xxxx xxxx"
    msg = EmailMessage()
    msg['Subject'] = "GOMS ERP - Login OTP"
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg.set_content(f"உங்கள் GOMS ERP லாகின் OTP: {otp_code}\nஇது 2 நிமிடங்களுக்கு மட்டுமே செல்லுபடியாகும்.")
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Email Error: {e}")

# ==========================================
# LOGIN ROUTE
# ==========================================
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("username"): return redirect(url_for("dashboard"))
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and verify_password(password, user["salt"], user["password_hash"]):
            if user["role"] in ["Admin", "MD", "GM"]:
                otp = str(random.randint(100000, 999999))
                session['temp_user'] = user["username"]
                session['temp_role'] = user["role"]
                session['current_otp'] = otp
                # ⚠️ TESTING ONLY - Remove/comment this flash in production
                flash(f"🔐 Your Login OTP is: {otp} (For Testing)", "warning")
                # send_otp_email("thileepanas@gmail.com", otp)
                return redirect(url_for("verify_otp"))
            else:
                session.permanent = True
                session["username"] = user["username"]
                session["role"] = user["role"]
                log_activity("Login", "User logged in successfully")
                return redirect(url_for("dashboard"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get('temp_user'):
        return redirect(url_for('login'))
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        if entered_otp == session.get('current_otp'):
            session.permanent = True
            session["username"] = session.pop('temp_user')
            session["role"] = session.pop('temp_role')
            session.pop('current_otp', None)
            log_activity("Login", "User logged in with OTP")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP! Please try again.", "error")
    return render_template("verify_otp.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    d = {}
    today = datetime.now()
    fy_start_year = today.year if today.month >= 4 else today.year - 1
    fy_start = f"{fy_start_year}-04-01"
    fy_end = f"{fy_start_year + 1}-03-31"

    d['total_projects'] = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    d['total_project_value'] = conn.execute("SELECT SUM(project_value) FROM projects").fetchone()[0] or 0

    gross_sales = conn.execute("""
        SELECT SUM(bi.basic_amount) FROM bill_items bi
        JOIN bills b ON bi.bill_id = b.id
        WHERE b.bill_date BETWEEN ? AND ?
    """, (fy_start, fy_end)).fetchone()[0] or 0

    total_cn = conn.execute("""
        SELECT SUM(amount) FROM accounts
        WHERE transaction_type = 'Credit Note'
        AND transaction_date BETWEEN ? AND ?
    """, (fy_start, fy_end)).fetchone()[0] or 0

    d['total_sales'] = gross_sales - total_cn
    d['total_labour'] = conn.execute("SELECT COUNT(*) FROM labour").fetchone()[0]
    d['total_income'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Income', 'Debit Note') AND transaction_date BETWEEN ? AND ?", (fy_start, fy_end)).fetchone()[0] or 0
    d['total_expense'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Expense', 'Credit Note') AND transaction_date BETWEEN ? AND ?", (fy_start, fy_end)).fetchone()[0] or 0
    d['low_stock_count'] = conn.execute("SELECT COUNT(*) FROM stock WHERE opening_stock <= reorder_level").fetchone()[0]
    d['pending_approvals'] = conn.execute("SELECT COUNT(*) FROM purchases WHERE md_approval='Pending'").fetchone()[0]
    d['pending_gm_approvals'] = conn.execute("SELECT COUNT(*) FROM po WHERE gm_approval='Pending'").fetchone()[0]
    try:
        d['pending_quotes'] = conn.execute("SELECT COUNT(*) FROM vendor_quotes WHERE status='Pending'").fetchone()[0]
    except:
        d['pending_quotes'] = 0
    d['recent_bills'] = conn.execute("SELECT * FROM bills ORDER BY id DESC LIMIT 5").fetchall()

    ps = conn.execute("SELECT COALESCE(status, 'Unknown') as status, COUNT(*) as count FROM projects GROUP BY status").fetchall()
    d['status_labels'] = [r['status'] for r in ps]
    d['status_counts'] = [r['count'] for r in ps]

    cash_flow = []
    for i in range(5, -1, -1):
        target_month = today.month - i
        target_year = today.year
        if target_month <= 0:
            target_month += 12
            target_year -= 1
        month_str = f"{target_year}-{target_month:02d}"
        income = conn.execute("SELECT SUM(amount) FROM accounts WHERE strftime('%Y-%m', transaction_date) = ? AND transaction_type IN ('Income', 'Debit Note')", (month_str,)).fetchone()[0] or 0
        expense = conn.execute("SELECT SUM(amount) FROM accounts WHERE strftime('%Y-%m', transaction_date) = ? AND transaction_type = 'Expense'", (month_str,)).fetchone()[0] or 0
        month_name = datetime(target_year, target_month, 1).strftime('%b %Y')
        cash_flow.append({"month": month_name, "income": income, "expense": expense})

    d['cash_flow_labels'] = [c['month'] for c in cash_flow]
    d['cash_flow_income'] = [c['income'] for c in cash_flow]
    d['cash_flow_expense'] = [c['expense'] for c in cash_flow]
    conn.close()
    return render_template("dashboard.html", **d, today=today, fy_str=f"{fy_start_year}-{(fy_start_year+1)%100:02d}")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ==========================================
# BUSINESS DEVELOPMENT - LEAD TRACKER
# ==========================================
@app.route("/leads", methods=["GET", "POST"])
def leads():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            lead_date = request.form.get("lead_date")
            client_name = request.form.get("client_name")
            project_name = request.form.get("project_name")
            if lead_date and client_name and project_name:
                conn.execute("""INSERT INTO leads
                    (lead_date, client_name, contact_person, phone, project_name, location, estimated_value, source, status, next_followup, remarks)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?)""",
                    (lead_date, client_name, request.form.get("contact_person"), request.form.get("phone"),
                     project_name, request.form.get("location"), float(request.form.get("estimated_value") or 0),
                     request.form.get("source"), request.form.get("next_followup"), request.form.get("remarks")))
                conn.commit()
                flash("New Lead added successfully!", "success")
            else:
                flash("Required fields missing!", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("leads"))
    all_leads = conn.execute("SELECT * FROM leads ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("leads.html", leads=all_leads, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/lead/update_status/<int:id>/<status>")
def update_lead_status(id, status):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE leads SET status=? WHERE id=?", (status, id))
    conn.commit()
    conn.close()
    flash(f"Lead marked as {status}!", "success")
    return redirect(url_for("leads"))

@app.route("/lead/convert_tender/<int:id>")
def convert_lead_to_tender(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    lead = conn.execute("SELECT * FROM leads WHERE id=?", (id,)).fetchone()
    if lead and lead['status'] == 'Won':
        existing = conn.execute("SELECT id FROM tenders WHERE tender_no=?", (lead['project_name'],)).fetchone()
        if not existing:
            conn.execute("""INSERT INTO tenders (tender_no, client_name, tender_date, status, estimated_value)
                            VALUES (?, ?, ?, 'Pending', ?)""",
                         (lead['project_name'], lead['client_name'], datetime.now().strftime("%Y-%m-%d"), lead['estimated_value']))
            conn.execute("UPDATE leads SET status='Converted to Tender' WHERE id=?", (id,))
            conn.commit()
            flash("Lead successfully converted to Tender!", "success")
            conn.close()
            return redirect(url_for("tenders"))
        else:
            flash("Tender with this Project Name already exists!", "warning")
    else:
        flash("Only 'Won' leads can be converted to Tender.", "error")
    conn.close()
    return redirect(url_for("leads"))
# ==========================================
# USERS & PASSWORDS
# ==========================================
@app.route("/users", methods=["GET", "POST"])
def users():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "GM"]:
        flash("Only MD and GM can manage users.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        r = request.form.get("role", "Site Supervisor")
        if not u or not p:
            if is_ajax: return jsonify({'status': 'error', 'message': 'Username & Password required.'})
            flash("Username/Password required.", "error")
        else:
            salt, pw = hash_password(p)
            try:
                conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)", (u, salt, pw, r))
                conn.commit()
                if is_ajax: return jsonify({'status': 'success', 'message': f"User '{u}' created!"})
                flash(f"User '{u}' created!", "success")
            except sqlite3.IntegrityError:
                if is_ajax: return jsonify({'status': 'error', 'message': 'Username already exists!'})
                flash("Username exists!", "error")
        conn.close()
        if is_ajax: return jsonify({'status': 'error', 'message': 'Something went wrong'})
        return redirect(url_for("users"))

    ul = conn.execute("SELECT id, username, role FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("users.html", users=ul)

@app.route("/users/delete/<int:id>")
def delete_user(id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "GM"]:
        flash("Only MD and GM can delete users.", "error")
        return redirect(url_for("users"))
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    conn = get_db()
    target = conn.execute("SELECT username, role FROM users WHERE id=?", (id,)).fetchone()

    if not target:
        if is_ajax: return jsonify({'status': 'error', 'message': 'User not found.'})
        flash("User not found.", "error")
    elif target["username"] == session.get("username"):
        if is_ajax: return jsonify({'status': 'error', 'message': 'You cannot delete yourself.'})
        flash("Cannot delete yourself.", "error")
    elif target["role"] == "MD":
        if session.get("role") != "MD":
            if is_ajax: return jsonify({'status': 'error', 'message': 'Only MD can delete another MD.'})
            flash("Only MD can delete another MD.", "error")
            conn.close()
            return redirect(url_for("users"))
        md_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='MD'").fetchone()[0]
        if md_count <= 1:
            if is_ajax: return jsonify({'status': 'error', 'message': 'Cannot delete the last MD user!'})
            flash("Cannot delete the last MD user!", "error")
            conn.close()
            return redirect(url_for("users"))
        conn.execute("DELETE FROM users WHERE id=?", (id,))
        conn.commit()
        if is_ajax: return jsonify({'status': 'success', 'message': 'User deleted.'})
        flash("User deleted.", "success")
    else:
        conn.execute("DELETE FROM users WHERE id=?", (id,))
        conn.commit()
        if is_ajax: return jsonify({'status': 'success', 'message': 'User deleted.'})
        flash("User deleted.", "success")

    conn.close()
    return redirect(url_for("users"))

@app.route("/users/edit/<int:id>", methods=["POST"])
def edit_user_role(id):
    if not session.get("username"): return redirect(url_for("login"))
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if session.get("role") not in ["MD", "GM"]:
        return jsonify({'status': 'error', 'message': 'Only MD and GM can change roles.'}) if is_ajax else redirect(url_for("users"))

    valid_roles = ["MD", "Admin", "GM", "Accountant", "Store Keeper", "Site Supervisor"]
    new_role = request.form.get("role")
    if new_role not in valid_roles:
        if is_ajax: return jsonify({'status': 'error', 'message': 'Invalid role.'})
        flash("Invalid role.", "error")
        return redirect(url_for("users"))

    conn = get_db()
    target = conn.execute("SELECT username, role FROM users WHERE id=?", (id,)).fetchone()

    if target and target["role"] == "MD" and new_role != "MD":
        if session.get("role") != "MD":
            if is_ajax: return jsonify({'status': 'error', 'message': 'Only MD can change another MD role.'})
            flash("Only MD can change another MD role.", "error")
            conn.close()
            return redirect(url_for("users"))
        md_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='MD'").fetchone()[0]
        if md_count <= 1:
            if is_ajax: return jsonify({'status': 'error', 'message': 'Cannot demote the last MD user!'})
            flash("Cannot demote the last MD user!", "error")
            conn.close()
            return redirect(url_for("users"))

    conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, id))
    conn.commit()
    log_activity("Edit Role", f"User {target['username']}: {target['role']} → {new_role}")
    conn.close()
    if is_ajax: return jsonify({'status': 'success', 'message': 'Role updated successfully!'})
    flash("Role updated.", "success")
    return redirect(url_for("users"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not session.get("username"): return redirect(url_for("login"))
    if request.method == "POST":
        old, new, confirm = request.form.get("old_password"), request.form.get("new_password"), request.form.get("confirm_password")
        if new != confirm: flash("Passwords do not match!", "error"); return redirect(url_for("change_password"))
        if len(new) < 6: flash("Password must be 6+ chars.", "error"); return redirect(url_for("change_password"))
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()
        if user and verify_password(old, user["salt"], user["password_hash"]):
            salt, pw_hash = hash_password(new)
            conn.execute("UPDATE users SET salt=?, password_hash=? WHERE id=?", (salt, pw_hash, user["id"]))
            conn.commit(); conn.close()
            flash("Password changed!", "success"); session.clear(); return redirect(url_for("login"))
        flash("Incorrect Old Password.", "error"); conn.close()
        return redirect(url_for("change_password"))
    return render_template("change_password.html")

@app.route("/activity_log")
def activity_log():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "GM"]:
        flash("Access Denied: Only MD and GM can view activity logs.", "error")
        return redirect(url_for("dashboard"))
    conn = get_db()
    logs = conn.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()
    return render_template("activity_log.html", logs=logs)

# ==========================================
# PROJECTS & TENDERS
# ==========================================
@app.route("/projects", methods=["GET", "POST"])
def projects():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == "POST":
        p_name, c_name = request.form.get("project_name", "").strip(), request.form.get("client_name", "").strip()
        if p_name and c_name:
            conn.execute("INSERT INTO projects (project_name, client_name, work_order, project_value, start_date, status) VALUES (?, ?, ?, ?, ?, ?)", (p_name, c_name, request.form.get("work_order"), float(request.form.get("project_value") or 0), request.form.get("start_date"), request.form.get("status", "Planning")))
            conn.commit()
            if is_ajax:
                return jsonify({'status': 'success', 'message': 'Project saved successfully!'})
            flash("Project saved!", "success")
            conn.close()
            return redirect(url_for("projects"))
        else:
            if is_ajax:
                return jsonify({'status': 'error', 'message': 'Project Name and Client Name are required!'})

    pl = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    d = conn.execute("SELECT party_name FROM parties WHERE party_type='Debtor' ORDER BY party_name").fetchall()
    conn.close()
    return render_template("projects.html", projects=pl, debtors=d)

@app.route("/projects/delete/<int:id>")
def delete_project(id):
    if not session.get("username"): return redirect(url_for("login"))
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
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
        if is_ajax: return jsonify({'status': 'success', 'message': 'Project deleted successfully!'})
        flash("Project and all related data deleted!", "success")
    else:
        if is_ajax: return jsonify({'status': 'error', 'message': 'Project not found.'})
        flash("Project not found!", "error")

    conn.close()
    return redirect(url_for("projects"))

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
    if not file or file.filename == '':
        flash("No file selected!", "error"); return redirect(url_for("tender_items", id=id))
    try:
        df = pd.read_excel(file)
        df.columns = df.columns.str.strip()
        req_cols = ['Description', 'Quantity', 'Unit', 'BOQ Supply Rate', 'BOQ Erection Rate']
        if not all(col in df.columns for col in req_cols):
            flash(f"Invalid format. Need: {', '.join(req_cols)}", "error")
            return redirect(url_for("tender_items", id=id))
        
        conn = get_db()

        existing_items = conn.execute(
            "SELECT description FROM tender_items WHERE tender_id=?", (id,)
        ).fetchall()
        existing_desc_set = {str(item[0]).strip().lower() for item in existing_items}
        
        added_count = 0
        skipped_count = 0

        for index, row in df.iterrows():
            if pd.notna(row['Description']) and str(row['Description']).strip() != "":
                desc = str(row['Description']).strip()
                
                if desc.lower() in existing_desc_set:
                    skipped_count += 1
                    continue

                q = float(row['Quantity']) if pd.notna(row['Quantity']) else 0
                sup_rate = float(row['BOQ Supply Rate']) if pd.notna(row['BOQ Supply Rate']) else 0
                ere_rate = float(row['BOQ Erection Rate']) if pd.notna(row['BOQ Erection Rate']) else 0
                c_sup_rate = float(row['Our Supply Rate']) if 'Our Supply Rate' in df.columns and pd.notna(row['Our Supply Rate']) else 0
                c_ere_rate = float(row['Our Erection Rate']) if 'Our Erection Rate' in df.columns and pd.notna(row['Our Erection Rate']) else 0
                total_rate = sup_rate + ere_rate
                amt = round(q * total_rate, 2)
                
                conn.execute("""INSERT INTO tender_items
                    (tender_id, description, unit, quantity, rate, supply_rate, erection_rate, company_supply_rate, company_erection_rate, amount)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (id, desc, str(row['Unit']).strip(), q, total_rate, sup_rate, ere_rate, c_sup_rate, c_ere_rate, amt))
                existing_desc_set.add(desc.lower())
                added_count += 1

        total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id=?", (id,)).fetchone()[0] or 0
        conn.execute("UPDATE tenders SET estimated_value=? WHERE id=?", (total, id))
        conn.commit(); conn.close()
        
        if skipped_count > 0:
            flash(f"Excel uploaded! {added_count} new items added, {skipped_count} duplicates skipped.", "success")
        else:
            flash("Excel uploaded with BOQ & Target Rates!", "success")
            
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
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

@app.route("/tender/item/delete/<int:item_id>", methods=["POST"])
def delete_tender_item(item_id):
    if not session.get("username"): return redirect(url_for("login"))
    
    conn = get_db()
    item = conn.execute("SELECT tender_id FROM tender_items WHERE id=?", (item_id,)).fetchone()
    
    if item:
        tender_id = item[0]
        conn.execute("DELETE FROM tender_items WHERE id=?", (item_id,))
        total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id=?", (tender_id,)).fetchone()[0] or 0
        conn.execute("UPDATE tenders SET estimated_value=? WHERE id=?", (total, tender_id))
        
        conn.commit()
        flash("Item deleted successfully!", "success")
    else:
        flash("Item not found!", "error")
        
    conn.close()
    return redirect(url_for("tender_items", id=tender_id))

@app.route("/tender/sample_excel")
def download_tender_sample():
    if not session.get("username"): return redirect(url_for("login"))
    data = {'Description': ['Sample Item 1', 'Sample Item 2'], 'Quantity': [10, 5], 'Unit': ['Nos', 'Mtr'], 'BOQ Supply Rate': [120000, 5000], 'BOQ Erection Rate': [60000, 1000], 'Our Supply Rate': [90000, 4000], 'Our Erection Rate': [40000, 800]}
    df = pd.DataFrame(data)
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    out.seek(0)
    return send_file(out, download_name="Sample_BOQ_Tender.xlsx", as_attachment=True)

@app.route("/tender/update_status/<int:id>/<status>")
def update_tender_status(id, status):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("UPDATE tenders SET status=? WHERE id=?", (status, id)); conn.commit(); conn.close()
    flash(f"Tender marked as {status}!", "success"); return redirect(url_for("tenders"))

@app.route("/tender/convert/<int:id>")
def convert_tender(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    t = conn.execute("SELECT * FROM tenders WHERE id=?", (id,)).fetchone()
    if t and t['status'] == 'Won':
        existing_project = conn.execute("SELECT id FROM projects WHERE project_name=?", (t['tender_no'],)).fetchone()
        if not existing_project:
            conn.execute("INSERT INTO projects (project_name, client_name, project_value, status) VALUES (?, ?, ?, 'In Progress')", (t['tender_no'], t['client_name'], t['estimated_value']))
        existing_boq = conn.execute("SELECT id FROM poq WHERE project_name=?", (t['tender_no'],)).fetchone()
        if not existing_boq:
            for item in conn.execute("SELECT * FROM tender_items WHERE tender_id=?", (id,)).fetchall():
                conn.execute("""INSERT INTO poq
                    (project_name, material_name, unit, quantity, actual_quantity, rate, amount, supply_rate, erection_rate, company_supply_rate, company_erection_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (t['tender_no'], item['description'], item['unit'], item['quantity'], item['quantity'], item['rate'], item['amount'], item['supply_rate'], item['erection_rate'], item['company_supply_rate'], item['company_erection_rate']))
            conn.commit()
            flash("Tender converted to Project! Estimation items copied to BOQ.", "success")
        else:
            flash("Project and BOQ already exist! Showing BOQ.", "info")
        conn.close()
        return redirect(url_for("poq", project=t['tender_no']))
    flash("Only 'Won' tenders can be converted to Projects.", "error")
    conn.close()
    return redirect(url_for("tenders"))

@app.route("/tender/pnl/<int:id>")
def tender_pnl(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    tender = conn.execute("SELECT * FROM tenders WHERE id=?", (id,)).fetchone()
    if not tender:
        flash("Tender not found!", "error"); conn.close(); return redirect(url_for("tenders"))
    items = conn.execute("SELECT * FROM tender_items WHERE tender_id=?", (id,)).fetchall()
    conn.close()
    pnl_data = []; total_client_val = 0; total_target_cost = 0; total_profit = 0
    for item in items:
        qty = item['quantity'] or 0
        client_rate = (item['supply_rate'] or 0) + (item['erection_rate'] or 0)
        client_val = qty * client_rate
        our_rate = (item['company_supply_rate'] or 0) + (item['company_erection_rate'] or 0)
        target_cost = qty * our_rate
        profit = client_val - target_cost
        pnl_data.append({"description": item['description'], "qty": qty, "unit": item['unit'], "client_rate": client_rate, "client_val": client_val, "our_rate": our_rate, "target_cost": target_cost, "profit": profit})
        total_client_val += client_val; total_target_cost += target_cost; total_profit += profit
    return render_template("tender_pnl.html", tender=tender, pnl_data=pnl_data, total_client_val=total_client_val, total_target_cost=total_target_cost, total_profit=total_profit)

# ==========================================
# HR MODULE - EMPLOYEES
# ==========================================
@app.route("/employees", methods=["GET", "POST"])
def employees():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor":
        flash("Access Denied", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    if request.method == "POST":
        try:
            emp_code = request.form.get("emp_code", "").strip()
            name = request.form.get("name", "").strip()
            if not emp_code or not name:
                flash("Employee Code and Name are required!", "error")
            else:
                conn.execute("""INSERT INTO employees
                    (emp_code, name, designation, department, join_date, phone, email, basic_salary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (emp_code, name, request.form.get("designation"), request.form.get("department"),
                     request.form.get("join_date"), request.form.get("phone"), request.form.get("email"),
                     float(request.form.get("basic_salary") or 0)))
                conn.commit()
                flash("Employee added successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Employee Code already exists!", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("employees"))
    emps = conn.execute("SELECT * FROM employees ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("employees.html", employees=emps)

@app.route("/employees/toggle/<int:id>")
def toggle_employee(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    emp = conn.execute("SELECT is_active FROM employees WHERE id=?", (id,)).fetchone()
    if emp:
        new_status = 0 if emp['is_active'] == 1 else 1
        conn.execute("UPDATE employees SET is_active=? WHERE id=?", (new_status, id))
        conn.commit()
        flash("Employee status updated.", "success")
    conn.close()
    return redirect(url_for("employees"))

@app.route("/employee/profile/<int:id>")
def employee_profile(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    emp = conn.execute("SELECT * FROM employees WHERE id=?", (id,)).fetchone()
    if not emp:
        flash("Employee not found!", "error"); conn.close(); return redirect(url_for("employees"))
    docs = conn.execute("SELECT * FROM employee_documents WHERE emp_id=? ORDER BY id DESC", (id,)).fetchall()
    conn.close()
    return render_template("employee_profile.html", emp=emp, docs=docs, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/employee/upload_doc/<int:id>", methods=["POST"])
def upload_employee_doc(id):
    if not session.get("username"): return redirect(url_for("login"))
    file = request.files.get("file")
    doc_name = request.form.get("doc_name")
    if file and file.filename != '' and doc_name:
        orig_filename = secure_filename(file.filename)
        ext = os.path.splitext(orig_filename)[1]
        new_filename = f"emp_{id}_{datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
        emp_upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'employees')
        os.makedirs(emp_upload_dir, exist_ok=True)
        file_path = os.path.join(emp_upload_dir, new_filename)
        file.save(file_path)
        conn = get_db()
        conn.execute("INSERT INTO employee_documents (emp_id, doc_name, file_name, upload_date) VALUES (?, ?, ?, ?)",
                     (id, doc_name, new_filename, datetime.now().strftime("%Y-%m-%d")))
        conn.commit(); conn.close()
        flash("Document uploaded successfully!", "success")
    else:
        flash("Please select a document name and file.", "error")
    return redirect(url_for("employee_profile", id=id))

@app.route("/employee/delete_doc/<int:doc_id>")
def delete_employee_doc(doc_id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    doc = conn.execute("SELECT * FROM employee_documents WHERE id=?", (doc_id,)).fetchone()
    if doc:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'employees', doc['file_name'])
        if os.path.exists(file_path): os.remove(file_path)
        conn.execute("DELETE FROM employee_documents WHERE id=?", (doc_id,))
        conn.commit()
        emp_id = doc['emp_id']
        conn.close()
        flash("Document deleted!", "success")
        return redirect(url_for("employee_profile", id=emp_id))
    conn.close()
    return redirect(url_for("employees"))

# ==========================================
# HR MODULE - ATTENDANCE, LEAVE, ADVANCES, PAYROLL
# ==========================================
@app.route("/staff_attendance", methods=["GET", "POST"])
def staff_attendance():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor":
        flash("Access Denied", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    d = request.args.get("date") or datetime.now().strftime("%Y-%m-%d")

    if request.method == "POST":
        if "attendance_date" in request.form:
            dt = request.form.get("attendance_date")
            conn.execute("DELETE FROM staff_attendance WHERE attendance_date=?", (dt,))
            for k, v in request.form.items():
                if k.startswith("status_"):
                    eid = k.split("_")[1]
                    conn.execute("INSERT INTO staff_attendance (emp_id, attendance_date, status) VALUES (?, ?, ?)", (eid, dt, v))
            conn.commit()
            flash("Staff Attendance saved manually!", "success")
            conn.close()
            return redirect(url_for("staff_attendance", date=dt))

        elif "import_excel" in request.form:
            file = request.files.get("file")
            if file:
                try:
                    df = pd.read_excel(file)
                    count = 0
                    for _, row in df.iterrows():
                        emp_code = str(row.get('Emp Code', '')).strip()
                        date_str = str(row.get('Date', ''))[:10]
                        status = str(row.get('Status', '')).strip().capitalize()
                        if emp_code and date_str and status:
                            emp = conn.execute("SELECT id FROM employees WHERE emp_code=?", (emp_code,)).fetchone()
                            if emp:
                                ex = conn.execute("SELECT id FROM staff_attendance WHERE emp_id=? AND attendance_date=?", (emp['id'], date_str)).fetchone()
                                if ex:
                                    conn.execute("UPDATE staff_attendance SET status=? WHERE id=?", (status, ex['id']))
                                else:
                                    conn.execute("INSERT INTO staff_attendance (emp_id, attendance_date, status) VALUES (?, ?, ?)", (emp['id'], date_str, status))
                                count += 1
                    conn.commit()
                    flash(f"Successfully imported {count} attendance records from Excel!", "success")
                except Exception as e:
                    flash(f"Error importing Excel: {str(e)}", "error")
            conn.close()
            return redirect(url_for("staff_attendance"))

    emps = conn.execute("SELECT id, name, emp_code, designation FROM employees WHERE is_active=1 ORDER BY name").fetchall()
    ea = conn.execute("SELECT * FROM staff_attendance WHERE attendance_date=?", (d,)).fetchall()
    # ✅ FIX: Convert sqlite3.Row to dict
    ad = {str(a['emp_id']): dict(a) for a in ea}
    conn.close()
    return render_template("staff_attendance.html", employees=emps, selected_date=d, att_dict=ad, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/leave_management", methods=["GET", "POST"])
def leave_management():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor":
        flash("Access Denied", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    if request.method == "POST":
        emp_id = request.form.get("emp_id"); start_date = request.form.get("start_date")
        end_date = request.form.get("end_date"); leave_type = request.form.get("leave_type"); reason = request.form.get("reason")
        if emp_id and start_date and end_date:
            conn.execute("INSERT INTO staff_leaves (emp_id, start_date, end_date, leave_type, reason) VALUES (?, ?, ?, ?, ?)", (emp_id, start_date, end_date, leave_type, reason))
            conn.commit()
            flash("Leave applied successfully!", "success")
        conn.close()
        return redirect(url_for("leave_management"))
    emps = conn.execute("SELECT id, name, emp_code FROM employees WHERE is_active=1 ORDER BY name").fetchall()
    leaves = conn.execute("""SELECT sl.*, e.name, e.emp_code FROM staff_leaves sl
        JOIN employees e ON sl.emp_id = e.id ORDER BY sl.id DESC""").fetchall()
    conn.close()
    return render_template("leave_management.html", employees=emps, leaves=leaves, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/leave_approve/<int:id>/<status>")
def leave_approve(id, status):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "Admin", "GM"]:
        flash("Only MD/GM can approve leaves.", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    conn.execute("UPDATE staff_leaves SET status=? WHERE id=?", (status, id))
    conn.commit(); conn.close()
    flash(f"Leave marked as {status}!", "success")
    return redirect(url_for("leave_management"))

@app.route("/staff_advances", methods=["GET", "POST"])
def staff_advances():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor":
        flash("Access Denied", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    if request.method == "POST":
        emp_id = request.form.get("emp_id")
        amount = float(request.form.get("amount") or 0)
        date = request.form.get("date")
        reason = request.form.get("reason")
        exp_type = request.form.get("exp_type", "Advance")

        if emp_id and amount > 0:
            # ✅ FIX: Fetch emp_name before using it
            emp = conn.execute("SELECT name FROM employees WHERE id=?", (emp_id,)).fetchone()
            emp_name = emp['name'] if emp else "Employee"
            conn.execute("INSERT INTO staff_advances (emp_id, date, amount, reason, status) VALUES (?, ?, ?, ?, ?)",
                         (emp_id, date, amount, f"[{exp_type}] {reason}", 'Approved'))
            conn.commit()
            flash(f"Successfully recorded {exp_type} for {emp_name}!", "success")
        conn.close()
        return redirect(url_for("staff_advances"))
    emps = conn.execute("SELECT id, name, emp_code FROM employees WHERE is_active=1 ORDER BY name").fetchall()
    advances = conn.execute("""SELECT sa.*, e.name, e.emp_code FROM staff_advances sa
        JOIN employees e ON sa.emp_id = e.id ORDER BY sa.id DESC""").fetchall()
    conn.close()
    return render_template("staff_advances.html", employees=emps, advances=advances, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/payroll", methods=["GET", "POST"])
def payroll():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "Admin", "GM", "Accountant"]:
        flash("Access Denied", "error"); return redirect(url_for("dashboard"))
    conn = get_db()
    selected_month = request.args.get("month") or datetime.now().strftime("%Y-%m")

    if request.method == "POST":
        try:
            emp_ids = request.form.getlist("emp_id[]")
            present_days_list = request.form.getlist("present_days[]")
            advance_list = request.form.getlist("advance[]")
            pf_list = request.form.getlist("pf[]")
            tds_list = request.form.getlist("tds[]")
            net_salary_list = request.form.getlist("net_salary[]")
            earned_gross_list = request.form.getlist("earned_gross[]")
            pay_date = request.form.get("payment_date") or datetime.now().strftime("%Y-%m-%d")

            for i in range(len(emp_ids)):
                eid = emp_ids[i]
                p_days = float(present_days_list[i] or 0)
                adv = float(advance_list[i] or 0)
                pf = float(pf_list[i] or 0)
                tds = float(tds_list[i] or 0)
                net_sal = float(net_salary_list[i] or 0)
                earned_gross = float(earned_gross_list[i] or 0)

                if net_sal >= 0 and earned_gross > 0:
                    exist = conn.execute("SELECT id FROM payroll WHERE emp_id=? AND month=?", (eid, selected_month)).fetchone()
                    if not exist:
                        emp = conn.execute("SELECT name FROM employees WHERE id=?", (eid,)).fetchone()
                        conn.execute("""INSERT INTO payroll
                            (emp_id, month, basic_salary, earned_gross, present_days, advance_deducted, pf_deducted, tds_deducted, net_salary, payment_date)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (eid, selected_month, earned_gross, earned_gross, p_days, adv, pf, tds, net_sal, pay_date))
                        conn.execute("""INSERT INTO accounts
                            (transaction_date, description, amount, transaction_type, project_name, paid_name, category)
                            VALUES (?, ?, ?, 'Expense', 'General', ?, 'Salary')""",
                            (pay_date, f"Salary for {selected_month}", earned_gross, emp['name']))
            conn.commit()
            flash("Payroll generated and saved to Accounts successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("payroll", month=selected_month))

    year, month = map(int, selected_month.split('-'))
    total_days_in_month = calendar.monthrange(year, month)[1]
    employees = conn.execute("SELECT * FROM employees WHERE is_active=1 ORDER BY name").fetchall()
    payroll_data = []

    for e in employees:
        present = conn.execute("""SELECT COUNT(*) FROM staff_attendance
            WHERE emp_id=? AND status='Present' AND strftime('%Y-%m', attendance_date)=?""",
            (e['id'], selected_month)).fetchone()[0]
        total_adv_given = conn.execute("""SELECT SUM(amount) FROM staff_advances
            WHERE emp_id=? AND strftime('%Y-%m', date) <= ?""", (e['id'], selected_month)).fetchone()[0] or 0
        total_adv_deducted = conn.execute("""SELECT SUM(advance_deducted) FROM payroll
            WHERE emp_id=? AND month < ?""", (e['id'], selected_month)).fetchone()[0] or 0
        adv = total_adv_given - total_adv_deducted
        if adv < 0: adv = 0
        hra = e['hra'] if 'hra' in e.keys() else 0
        allow = e['allowances'] if 'allowances' in e.keys() else 0
        pf_fixed = e['pf_amount'] if 'pf_amount' in e.keys() else 0
        tds_pct = e['tds_percent'] if 'tds_percent' in e.keys() else 0
        gross_monthly = (e['basic_salary'] or 0) + (hra or 0) + (allow or 0)
        daily_wage = gross_monthly / total_days_in_month if total_days_in_month > 0 else 0
        earned_gross = round(daily_wage * present, 2)
        tds_amount = round(earned_gross * (tds_pct / 100), 2)
        net_salary = round(earned_gross - adv - pf_fixed - tds_amount, 2)
        if net_salary < 0: net_salary = 0
        existing_payroll = conn.execute("SELECT * FROM payroll WHERE emp_id=? AND month=?", (e['id'], selected_month)).fetchone()
        payroll_data.append({
            "id": e['id'], "name": e['name'], "emp_code": e['emp_code'],
            "gross": gross_monthly, "present_days": present,
            "advance": adv, "pf": pf_fixed, "tds_pct": tds_pct, "tds": tds_amount,
            "earned_gross": earned_gross, "net": net_salary,
            "is_saved": True if existing_payroll else False
        })
    conn.close()
    return render_template("payroll.html", payroll_data=payroll_data, selected_month=selected_month, total_days=total_days_in_month, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/payroll/print/<int:id>/<month>")
def print_payroll(id, month):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    emp = conn.execute("SELECT * FROM employees WHERE id=?", (id,)).fetchone()
    pay = conn.execute("SELECT * FROM payroll WHERE emp_id=? AND month=?", (id, month)).fetchone()
    conn.close()
    if not emp or not pay:
        flash("Payroll record not found!", "error"); return redirect(url_for("payroll", month=month))
    year, m = map(int, month.split('-'))
    total_days = calendar.monthrange(year, m)[1]
    amount_in_words = num_to_words(round(pay['net_salary']))
    return render_template("print_payroll.html", emp=emp, pay=pay, total_days=total_days, amount_in_words=amount_in_words)

# ==========================================
# DOCUMENT VAULT & BULK IMPORT
# ==========================================
@app.route("/documents", methods=["GET", "POST"])
def documents():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    try:
        sp = request.args.get("project", "")
        if request.method == "POST":
            sp = request.form.get("project_name")
            doc_name = request.form.get("doc_name")
            file = request.files.get("file")
            if file and file.filename != '' and sp and doc_name:
                orig_filename = secure_filename(file.filename)
                ext = os.path.splitext(orig_filename)[1]
                new_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                file.save(file_path)
                conn.execute("INSERT INTO project_documents (project_name, doc_name, file_name, upload_date) VALUES (?, ?, ?, ?)",
                             (sp, doc_name, new_filename, datetime.now().strftime("%Y-%m-%d")))
                conn.commit()
                flash("Document uploaded successfully!", "success")
            else:
                flash("Please select project, enter document name, and choose a file.", "error")
            conn.close()
            return redirect(url_for("documents", project=sp))
        project_list = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
        doc_list = []
        if sp:
            doc_list = conn.execute("SELECT * FROM project_documents WHERE TRIM(project_name)=TRIM(?) ORDER BY id DESC", (sp,)).fetchall()
        today = datetime.now().strftime("%Y-%m-%d")
        return render_template("documents.html", project_list=project_list, selected_project=sp, doc_list=doc_list, today=today)
    except Exception as e:
        return f"<h2 style='color:red; padding:20px;'>Error Loading Document Vault:</h2><p style='padding:20px; font-size:18px;'>{str(e)}</p>"
    finally:
        if conn: conn.close()

@app.route("/documents/delete/<int:id>")
def delete_document(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    doc = conn.execute("SELECT * FROM project_documents WHERE id=?", (id,)).fetchone()
    if doc:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc['file_name'])
        if os.path.exists(file_path): os.remove(file_path)
        conn.execute("DELETE FROM project_documents WHERE id=?", (id,))
        conn.commit()
        flash("Document deleted!", "success")
    conn.close()
    return redirect(url_for("documents", project=request.args.get("project", "")))

@app.route("/bulk_import", methods=["GET", "POST"])
def bulk_import():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["Admin", "GM"]:
        flash("Access Denied: Only Admin/GM can import bulk data.", "error")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        form_type = request.form.get("form_type")
        file = request.files.get("file")
        if not file or file.filename == '':
            flash("No file selected!", "error"); return redirect(url_for("bulk_import"))
        try:
            df = pd.read_excel(file)
            conn = get_db(); cur = conn.cursor(); count = 0
            if form_type == "party":
                req_cols = ['Party Name', 'Party Type', 'GSTIN']
                if not all(col in df.columns for col in req_cols):
                    flash(f"Invalid format. Need columns: {', '.join(req_cols)}", "error")
                    return redirect(url_for("bulk_import"))
                for _, row in df.iterrows():
                    name = str(row['Party Name']).strip() if pd.notna(row['Party Name']) else ""
                    ptype = str(row['Party Type']).strip() if pd.notna(row['Party Type']) else "Debtor"
                    gstin = str(row['GSTIN']).strip() if pd.notna(row['GSTIN']) else ""
                    if name and gstin and not conn.execute("SELECT id FROM parties WHERE party_name=? OR gstin=?", (name, gstin)).fetchone():
                        cur.execute("INSERT INTO parties (party_name, party_type, gstin, contact_number, email, address, opening_balance) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    (name, ptype, gstin,
                                     str(row.get('Contact', '')) if pd.notna(row.get('Contact')) else '',
                                     str(row.get('Email', '')) if pd.notna(row.get('Email')) else '',
                                     str(row.get('Address', '')) if pd.notna(row.get('Address')) else '',
                                     float(row.get('Opening Balance', 0)) if pd.notna(row.get('Opening Balance')) else 0))
                        count += 1
            elif form_type == "project":
                req_cols = ['Project Name', 'Client Name']
                if not all(col in df.columns for col in req_cols):
                    flash(f"Invalid format. Need columns: {', '.join(req_cols)}", "error")
                    return redirect(url_for("bulk_import"))
                for _, row in df.iterrows():
                    pname = str(row['Project Name']).strip() if pd.notna(row['Project Name']) else ""
                    cname = str(row['Client Name']).strip() if pd.notna(row['Client Name']) else ""
                    if pname and cname and not conn.execute("SELECT id FROM projects WHERE project_name=?", (pname,)).fetchone():
                        start_date = str(row.get('Start Date', ''))[:10] if pd.notna(row.get('Start Date')) else ''
                        cur.execute("INSERT INTO projects (project_name, client_name, work_order, project_value, start_date, status) VALUES (?, ?, ?, ?, ?, ?)",
                                    (pname, cname,
                                     str(row.get('Work Order', '')) if pd.notna(row.get('Work Order')) else '',
                                     float(row.get('Project Value', 0)) if pd.notna(row.get('Project Value')) else 0,
                                     start_date,
                                     str(row.get('Status', 'Planning')) if pd.notna(row.get('Status')) else 'Planning'))
                        count += 1
            conn.commit(); conn.close()
            flash(f"Successfully imported {count} records!", "success")
        except Exception as e:
            flash(f"Error processing Excel: {str(e)}", "error")
        return redirect(url_for("bulk_import"))
    return render_template("bulk_import.html")

@app.route("/download_sample/<type>")
def download_sample(type):
    if not session.get("username"): return redirect(url_for("login"))
    out = io.BytesIO()
    if type == 'party':
        df = pd.DataFrame({'Party Name': ['ABC Traders', 'XYZ Builders'], 'Party Type': ['Creditor', 'Debtor'], 'GSTIN': ['33AAACG3020F1ZF', '33AACFV0222D1ZY'], 'Contact': ['9876543210', '9876543211'], 'Email': ['abc@test.com', 'xyz@test.com'], 'Address': ['Chennai', 'Coimbatore'], 'Opening Balance': [0, 0]})
    elif type == 'project':
        df = pd.DataFrame({'Project Name': ['Srinivas Towers', 'TNHB Phase 2'], 'Client Name': ['XYZ Builders', 'ABC Builders'], 'Work Order': ['WO-001', 'WO-002'], 'Project Value': [1000000, 5000000], 'Start Date': ['2026-04-01', '2026-05-01'], 'Status': ['In Progress', 'Planning']})
    else:
        return "Invalid type"
    with pd.ExcelWriter(out, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    out.seek(0)
    return send_file(out, download_name=f"{type}_sample.xlsx", as_attachment=True)
# ==========================================
# INDENT (MATERIAL REQUEST)
# ==========================================
@app.route("/indents", methods=["GET", "POST"])
def indents():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    sp = request.args.get("project", "")

    if request.method == "POST":
        sp = request.form.get("project_name")
        indent_date = request.form.get("indent_date")
        requested_by = request.form.get("requested_by")
        if not sp or not indent_date:
            flash("Project and Date are required!", "error"); return redirect(url_for("indents"))
        try:
            materials = request.form.getlist("material_name[]")
            quantities = request.form.getlist("quantity[]")
            remarks = request.form.getlist("remarks[]")
            for i in range(len(materials)):
                if materials[i].strip() and float(quantities[i] or 0) > 0:
                    mat_name = materials[i].strip()
                    req_qty = float(quantities[i])
                    boq_item = conn.execute("SELECT actual_quantity, quantity FROM poq WHERE TRIM(project_name)=TRIM(?) AND TRIM(material_name)=TRIM(?)", (sp, mat_name)).fetchone()
                    if not boq_item:
                        flash(f"Error: Material '{mat_name}' is not in this Project's BOQ.", "error")
                        conn.close(); return redirect(url_for("indents", project=sp))
                    boq_qty = boq_item['actual_quantity'] if boq_item['actual_quantity'] else (boq_item['quantity'] or 0)
                    already_indented = conn.execute("""SELECT SUM(ii.quantity) FROM indent_items ii
                        JOIN indents i ON ii.indent_id = i.id
                        WHERE TRIM(i.project_name)=TRIM(?) AND TRIM(ii.material_name)=TRIM(?) AND i.status != 'Cancelled'""",
                        (sp, mat_name)).fetchone()[0] or 0
                    remaining = boq_qty - already_indented
                    if req_qty > remaining + 0.01:
                        flash(f"Validation Error: Cannot indent {req_qty} of '{mat_name}'. Only {remaining:.2f} qty remaining in Actual BOQ.", "error")
                        conn.close(); return redirect(url_for("indents", project=sp))
            cur = conn.cursor()
            cur.execute("INSERT INTO indents (project_name, indent_date, requested_by) VALUES (?, ?, ?)", (sp, indent_date, requested_by))
            iid = cur.lastrowid
            for i in range(len(materials)):
                if materials[i].strip() and float(quantities[i] or 0) > 0:
                    cur.execute("INSERT INTO indent_items (indent_id, material_name, quantity, remarks) VALUES (?, ?, ?, ?)", (iid, materials[i], float(quantities[i]), remarks[i]))
            conn.commit()
            flash("Material Indent created successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("indents", project=sp))

    try:
        project_list = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
        boq_data = []; boq_dict = {}
        if sp:
            boq_items = conn.execute("SELECT * FROM poq WHERE TRIM(project_name)=TRIM(?)", (sp,)).fetchall()
            for item in boq_items:
                mat_name = item['material_name']
                already_indented = conn.execute("""SELECT SUM(ii.quantity) FROM indent_items ii
                    JOIN indents i ON ii.indent_id = i.id
                    WHERE TRIM(i.project_name)=TRIM(?) AND TRIM(ii.material_name)=TRIM(?) AND i.status != 'Cancelled'""",
                    (sp, mat_name)).fetchone()[0] or 0
                total_boq_qty = item['actual_quantity'] if item['actual_quantity'] else (item['quantity'] or 0)
                remaining = total_boq_qty - already_indented
                if remaining > 0.01:
                    boq_data.append({"material_name": item['material_name'], "unit": item['unit'], "boq_qty": total_boq_qty, "indented_qty": already_indented, "remaining_qty": remaining})
                    boq_dict[mat_name.strip().upper()] = remaining
        indent_list = conn.execute("""SELECT i.*, COUNT(ii.id) as item_count FROM indents i
            LEFT JOIN indent_items ii ON i.id = ii.indent_id
            GROUP BY i.id ORDER BY i.id DESC""").fetchall()
        conn.close()
        today = datetime.now().strftime("%Y-%m-%d")
        return render_template("indents.html", project_list=project_list, selected_project=sp, boq_data=boq_data, indents=indent_list, today=today, boq_dict=boq_dict)
    except Exception as e:
        conn.close()
        return f"<h2 style='color:red; padding:20px;'>Error Loading Indents:</h2><p style='padding:20px; font-size:18px;'>{str(e)}</p>"

@app.route("/indent/print/<int:id>")
def print_indent(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    indent = conn.execute("SELECT * FROM indents WHERE id=?", (id,)).fetchone()
    if not indent:
        flash("Not found", "error"); conn.close(); return redirect(url_for("indents"))
    items = conn.execute("SELECT * FROM indent_items WHERE indent_id=?", (id,)).fetchall()
    project = conn.execute("SELECT * FROM projects WHERE TRIM(project_name)=TRIM(?)", (indent['project_name'],)).fetchone()
    conn.close()
    return render_template("print_indent.html", indent=indent, items=items, project=project)

@app.route("/indent/cancel/<int:id>")
def cancel_indent(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    indent = conn.execute("SELECT project_name, status FROM indents WHERE id=?", (id,)).fetchone()
    if indent:
        if indent['status'] == 'PO Created':
            flash("Cannot cancel an indent for which a PO is already created!", "error")
        else:
            conn.execute("UPDATE indents SET status='Cancelled' WHERE id=?", (id,))
            conn.commit()
            flash("Indent cancelled successfully!", "success")
    else:
        flash("Indent not found!", "error")
    conn.close()
    return redirect(url_for("indents", project=indent['project_name'] if indent else ""))

@app.route("/indent/<int:id>/quotes", methods=["GET", "POST"])
def indent_quotes(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    try:
        indent = conn.execute("SELECT * FROM indents WHERE id=?", (id,)).fetchone()
        if not indent:
            flash("Indent not found", "error"); conn.close(); return redirect(url_for("indents"))
        raw_items = conn.execute("SELECT * FROM indent_items WHERE indent_id=?", (id,)).fetchall()
        if request.method == "POST":
            vendor_name = request.form.get("vendor_name", "").strip()
            brand_name = request.form.get("brand_name", "").strip()
            quote_date = request.form.get("quote_date")
            delivery_days = int(request.form.get("delivery_days") or 0)
            payment_terms = request.form.get("payment_terms", "").strip()
            tech_remarks = request.form.get("technical_remarks", "").strip()
            if not vendor_name or not brand_name:
                flash("Vendor Name and Brand Name are required!", "error")
            else:
                cur = conn.cursor()
                cur.execute("""INSERT INTO vendor_quotes (indent_id, vendor_name, brand_name, quote_date, delivery_days, payment_terms, technical_remarks)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""", (id, vendor_name, brand_name, quote_date, delivery_days, payment_terms, tech_remarks))
                qid = cur.lastrowid
                rates = request.form.getlist("rate[]")
                total_amt = 0
                for i, item in enumerate(raw_items):
                    rate = float(rates[i] or 0)
                    amt = round(item['quantity'] * rate, 2)
                    total_amt += amt
                    cur.execute("INSERT INTO quote_items (quote_id, indent_item_id, material_name, rate, amount) VALUES (?, ?, ?, ?, ?)",
                                (qid, item['id'], item['material_name'], rate, amt))
                cur.execute("UPDATE vendor_quotes SET total_amount=? WHERE id=?", (round(total_amt, 2), qid))
                conn.commit()
                flash("Vendor Quotation added successfully!", "success")
            conn.close()
            return redirect(url_for("indent_quotes", id=id))
        enriched_items = []
        for item in raw_items:
            item_dict = dict(item)
            last_pur = conn.execute("""SELECT pi.rate FROM purchase_items pi
                JOIN purchases p ON pi.purchase_id = p.id
                WHERE TRIM(pi.material_name) = TRIM(?)
                ORDER BY p.invoice_date DESC, pi.id DESC LIMIT 1""", (item_dict['material_name'],)).fetchone()
            item_dict['last_rate'] = last_pur['rate'] if last_pur else 0
            boq_rate = conn.execute("""SELECT company_supply_rate FROM poq
                WHERE TRIM(project_name) = TRIM(?) AND TRIM(material_name) = TRIM(?)""",
                (indent['project_name'], item_dict['material_name'])).fetchone()
            item_dict['budget_rate'] = boq_rate['company_supply_rate'] if boq_rate else 0
            enriched_items.append(item_dict)
        quotes = conn.execute("SELECT * FROM vendor_quotes WHERE indent_id=? ORDER BY id DESC", (id,)).fetchall()
        conn.close()
        return render_template("indent_quotes.html", indent=indent, items=enriched_items, quotes=quotes, today=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        if conn: conn.close()
        return f"<h2 style='color:red; padding:20px;'>Error:</h2><p style='padding:20px;'>{str(e)}</p>"

@app.route("/indent/<int:id>/comparison")
def quote_comparison(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    indent = conn.execute("SELECT * FROM indents WHERE id=?", (id,)).fetchone()
    if not indent:
        flash("Indent not found", "error"); conn.close(); return redirect(url_for("indents"))
    items = conn.execute("SELECT * FROM indent_items WHERE indent_id=?", (id,)).fetchall()
    quotes = conn.execute("SELECT * FROM vendor_quotes WHERE indent_id=? ORDER BY total_amount ASC", (id,)).fetchall()
    matrix = {}; rankings = {}
    for item in items:
        matrix[item['id']] = {}; rankings[item['id']] = {}; item_rates = []
        for q in quotes:
            qi = conn.execute("SELECT rate FROM quote_items WHERE quote_id=? AND indent_item_id=?", (q['id'], item['id'])).fetchone()
            rate = qi['rate'] if qi else 0
            matrix[item['id']][q['id']] = rate
            if rate > 0:
                item_rates.append((rate, q['id'], q['brand_name'] or 'Unspecified'))
        brand_groups = {}
        for rate, q_id, brand in item_rates:
            b = brand.strip().lower()
            if b not in brand_groups: brand_groups[b] = []
            brand_groups[b].append((rate, q_id))
        for b, rates in brand_groups.items():
            rates.sort(key=lambda x: x[0])
            for rank, (rate, q_id) in enumerate(rates, start=1):
                rankings[item['id']][q_id] = rank
    conn.close()
    return render_template("quote_comparison.html", indent=indent, items=items, quotes=quotes, matrix=matrix, rankings=rankings)

@app.route("/quote/approve/<int:quote_id>")
def approve_quote(quote_id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor": return redirect(url_for("dashboard"))
    conn = get_db()
    quote = conn.execute("SELECT * FROM vendor_quotes WHERE id=?", (quote_id,)).fetchone()
    if quote:
        conn.execute("UPDATE vendor_quotes SET status='Approved' WHERE id=?", (quote_id,))
        conn.execute("UPDATE vendor_quotes SET status='Rejected' WHERE indent_id=? AND id!=?", (quote['indent_id'], quote_id))
        conn.execute("UPDATE indents SET status='Approved' WHERE id=?", (quote['indent_id'],))
        log_activity("Approve Quote", f"Approved Vendor Quote ID: {quote_id}")
        conn.commit()
        flash(f"Quotation from {quote['vendor_name']} Approved! Ready for PO Generation.", "success")
    else:
        flash("Quote not found!", "error")
    conn.close()
    return redirect(url_for("quote_comparison", id=quote['indent_id'] if quote else 0))

@app.route("/generate_po/<int:quote_id>")
def generate_po_from_quote(quote_id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor": return redirect(url_for("dashboard"))
    conn = get_db()
    try:
        quote = conn.execute("SELECT * FROM vendor_quotes WHERE id=?", (quote_id,)).fetchone()
        if not quote or quote['status'] != 'Approved':
            flash("Invalid Quote or Quote not approved yet!", "error")
            conn.close(); return redirect(url_for("indents"))
        vendor_exists = conn.execute("SELECT id FROM parties WHERE TRIM(party_name)=TRIM(?) AND party_type='Creditor'", (quote['vendor_name'],)).fetchone()
        if not vendor_exists:
            flash(f"Vendor '{quote['vendor_name']}' not found in Party Master. Please add them as a Creditor first.", "error")
            conn.close(); return redirect(url_for("parties", new_name=quote['vendor_name']))
        indent = conn.execute("SELECT * FROM indents WHERE id=?", (quote['indent_id'],)).fetchone()
        existing_po = conn.execute("SELECT id FROM po WHERE quotation_no=?", (f"IND-{indent['id']}",)).fetchone()
        if existing_po:
            flash("PO already generated for this Indent!", "warning")
            conn.close(); return redirect(url_for("po"))
        cur = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        cur.execute("""INSERT INTO po (project_name, vendor_name, po_date, quotation_no, gm_approval)
            VALUES (?, ?, ?, ?, 'Approved')""", (indent['project_name'], quote['vendor_name'], today, f"IND-{indent['id']}"))
        po_id = cur.lastrowid
        quote_items = conn.execute("SELECT * FROM quote_items WHERE quote_id=?", (quote_id,)).fetchall()
        for qi in quote_items:
            mat_unit = conn.execute("SELECT unit FROM stock WHERE TRIM(material_name)=TRIM(?)", (qi['material_name'],)).fetchone()
            unit = mat_unit['unit'] if mat_unit else "Nos"
            indent_item = conn.execute("SELECT quantity FROM indent_items WHERE id=?", (qi['indent_item_id'],)).fetchone()
            qty = indent_item['quantity'] if indent_item else 0
            cur.execute("""INSERT INTO po_items (po_id, material_name, quantity, unit, rate)
                VALUES (?, ?, ?, ?, ?)""", (po_id, qi['material_name'], qty, unit, qi['rate']))
        conn.execute("UPDATE indents SET status='PO Created' WHERE id=?", (indent['id'],))
        conn.commit()
        flash(f"Purchase Order generated successfully for {quote['vendor_name']}!", "success")
        conn.close()
        return redirect(url_for("edit_po", id=po_id))
    except Exception as e:
        if conn: conn.close()
        return f"<h2 style='color:red; padding:20px;'>Error Generating PO:</h2><p style='padding:20px; font-size:18px;'>{str(e)}</p>"

# ==========================================
# PURCHASES
# ==========================================
@app.route("/purchases", methods=["GET", "POST"])
def purchases():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            p_name, s_name, inv = request.form.get("project_name"), request.form.get("supplier_name"), request.form.get("invoice_number")
            if not p_name or not s_name or not inv:
                flash("Project, Supplier, and Invoice Number are required.", "error")
            else:
                cur = conn.cursor()
                cur.execute("INSERT INTO purchases (po_number, project_name, supplier_name, invoice_number, invoice_date, subtotal, gst_amount, total_amount) VALUES (?, ?, ?, ?, ?, 0, 0, 0)", (request.form.get("po_number", "Multiple"), p_name, s_name, inv, request.form.get("invoice_date")))
                pid = cur.lastrowid
                g_total = 0
                mats = request.form.getlist("material_name[]"); qtys = request.form.getlist("quantity[]")
                rates = request.form.getlist("rate[]"); gsts = request.form.getlist("gst_rate[]")
                po_item_ids = request.form.getlist("po_item_id[]")
                for i in range(len(mats)):
                    if mats[i].strip():
                        q = float(qtys[i] or 0); r = float(rates[i] or 0); g = float(gsts[i] or 0)
                        po_item_id = po_item_ids[i] if i < len(po_item_ids) and po_item_ids[i] else None
                        if po_item_id:
                            po_info = conn.execute("SELECT quantity FROM po_items WHERE id=?", (po_item_id,)).fetchone()
                            already_purchased = conn.execute("SELECT SUM(quantity) FROM purchase_items WHERE po_item_id=?", (po_item_id,)).fetchone()[0] or 0
                            if po_info:
                                remaining_po_qty = po_info['quantity'] - already_purchased
                                if q > remaining_po_qty + 0.01:
                                    flash(f"Validation Error: Cannot purchase {q} of '{mats[i]}'. Only {remaining_po_qty} remaining in PO.", "error")
                                    conn.rollback(); conn.close(); return redirect(url_for("purchases"))
                        b_amt, g_amt = round(q*r, 2), round(q*r*(g/100), 2)
                        conn.execute("INSERT INTO purchase_items (purchase_id, po_item_id, material_name, description, quantity, rate, gst_rate, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (pid, po_item_id, mats[i], request.form.getlist("description[]")[i], q, r, g, b_amt+g_amt))
                        conn.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, 'Receipt', ?, ?, ?, ?)", (mats[i], request.form.get("invoice_date"), inv, p_name, q, r))
                        g_total += b_amt + g_amt
                tds_pct = float(request.form.get("tds_percent") or 0)
                ret_pct = float(request.form.get("retention_percent") or 0)
                tds_amt = g_total * (tds_pct / 100)
                ret_amt = g_total * (ret_pct / 100)
                net_payable = g_total - tds_amt - ret_amt
                conn.execute("UPDATE purchases SET total_amount=?, tds_percent=?, retention_percent=?, net_payable=? WHERE id=?", (round(g_total, 2), tds_pct, ret_pct, round(net_payable, 2), pid))
                conn.commit()
                flash("Purchase Invoice saved with TDS/Retention! Sent for MD Approval.", "success")
                conn.close()
                return redirect(url_for("purchases"))
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
    pl = conn.execute("SELECT * FROM purchases ORDER BY id DESC").fetchall()
    mats = conn.execute("SELECT material_name, unit FROM stock ORDER BY material_name").fetchall()
    # ✅ FIXED: Correct JOIN condition (po_items.po_id = po.id)
    po_items = conn.execute("""
        SELECT po.id as po_id, po.project_name, po.vendor_name, po_items.id as po_item_id, po_items.material_name,
               po_items.quantity as po_qty, po_items.rate, po_items.unit,
               IFNULL((SELECT SUM(pi.quantity) FROM purchase_items pi WHERE pi.po_item_id = po_items.id), 0) as purchased_qty
        FROM po JOIN po_items ON po_items.po_id = po.id WHERE po.gm_approval='Approved'
    """).fetchall()
    final_po_items = []
    for item in po_items:
        rem = item['po_qty'] - item['purchased_qty']
        if rem > 0.01:
            d = dict(item); d['remaining_qty'] = rem
            final_po_items.append(d)
    conn.close()
    return render_template("purchases.html", purchases=pl, materials=[dict(r) for r in mats], po_items_list=final_po_items)
# ==========================================
# GM / MD APPROVAL
# ==========================================
@app.route("/gm_approval")
def gm_approval():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    pp = conn.execute("SELECT * FROM po WHERE gm_approval='Pending' ORDER BY id DESC").fetchall()
    ap = conn.execute("SELECT * FROM po WHERE gm_approval='Approved' ORDER BY id DESC").fetchall()
    ppt = []
    for p in pp:
        it = conn.execute("SELECT quantity, rate FROM po_items WHERE po_id=?", (p['id'],)).fetchall()
        d = dict(p)
        d['total'] = round(sum((i['quantity'] or 0)*(i['rate'] or 0) for i in it)*1.18, 2)
        ppt.append(d)
    conn.close()
    return render_template("gm_approval.html", pending=ppt, approved=ap)

@app.route("/gm_approve/<int:id>")
def gm_approve(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE po SET gm_approval='Approved' WHERE id=?", (id,))
    conn.commit(); conn.close()
    flash("Approved!", "success")
    return redirect(url_for("gm_approval"))

@app.route("/md_approval")
def md_approval():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    p = conn.execute("SELECT * FROM purchases WHERE md_approval='Pending' ORDER BY id DESC").fetchall()
    a = conn.execute("SELECT * FROM purchases WHERE md_approval='Approved' ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("md_approval.html", pending=p, approved=a)

@app.route("/md_approve/<int:id>", methods=["POST"])
def md_approve(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE purchases SET md_approval='Approved' WHERE id=?", (id,))
    conn.commit(); conn.close()
    flash("Bill Approved! Ready for Payment.", "success")
    return redirect(url_for("md_approval"))

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

# ==========================================
# PURCHASE ORDER (PO)
# ==========================================
@app.route("/po", methods=["GET", "POST"])
def po():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if request.method == "POST":
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO po (project_name, vendor_name, po_date, delivery_address, quotation_no, gm_approval) VALUES (?, ?, ?, ?, ?, 'Pending')", (request.form.get("project_name"), request.form.get("vendor_name"), request.form.get("po_date"), request.form.get("delivery_address"), request.form.get("quotation_no")))
            pid = cur.lastrowid
            for i in range(len(request.form.getlist("material_name[]"))):
                if request.form.getlist("material_name[]")[i].strip():
                    cur.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate, gst_rate) VALUES (?, ?, ?, ?, ?, ?, ?)", (pid, request.form.getlist("material_name[]")[i], request.form.getlist("hsn_code[]")[i], float(request.form.getlist("quantity[]")[i] or 0), request.form.getlist("unit[]")[i], float(request.form.getlist("rate[]")[i] or 0), float(request.form.getlist("gst_rate[]")[i] or 18)))
            conn.commit()
            if is_ajax: return jsonify({'status': 'success', 'message': 'PO created successfully!'})
            flash("PO created!", "success")
        except Exception as e:
            if is_ajax: return jsonify({'status': 'error', 'message': str(e)})
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("po"))
    pol = conn.execute("SELECT * FROM po ORDER BY id DESC").fetchall()
    pot = []
    for p in pol:
        it = conn.execute("SELECT quantity, rate, gst_rate FROM po_items WHERE po_id=?", (p['id'],)).fetchall()
        d = dict(p)
        d['total'] = round(sum((i['quantity'] or 0)*(i['rate'] or 0)*(1 + (i['gst_rate'] or 18)/100) for i in it), 2)
        pot.append(d)
    pl = conn.execute("SELECT project_name FROM projects").fetchall()
    v = conn.execute("SELECT party_name FROM parties WHERE party_type='Creditor' AND is_blocked=0").fetchall()
    m = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close()
    return render_template("po.html", po_list=pot, project_list=pl, vendors=v, materials=m)

@app.route("/po/edit/<int:id>", methods=["GET", "POST"])
def edit_po(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    new_vendor = request.args.get("new_vendor", "")
    if request.method == "POST":
        project_name = request.form.get("project_name"); vendor_name = request.form.get("vendor_name")
        po_date = request.form.get("po_date"); delivery_address = request.form.get("delivery_address")
        quotation_no = request.form.get("quotation_no"); action = request.form.get("action")
        conn.execute("UPDATE po SET project_name=?, vendor_name=?, po_date=?, delivery_address=?, quotation_no=? WHERE id=?", (project_name, vendor_name, po_date, delivery_address, quotation_no, id))
        conn.execute("DELETE FROM po_items WHERE po_id=?", (id,))
        for i in range(len(request.form.getlist("material_name[]"))):
            if request.form.getlist("material_name[]")[i].strip():
                conn.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate, gst_rate) VALUES (?, ?, ?, ?, ?, ?, ?)", (id, request.form.getlist("material_name[]")[i], request.form.getlist("hsn_code[]")[i], float(request.form.getlist("quantity[]")[i] or 0), request.form.getlist("unit[]")[i], float(request.form.getlist("rate[]")[i] or 0), float(request.form.getlist("gst_rate[]")[i] or 18)))
        conn.commit(); conn.close()
        if action == "save_and_print": return redirect(url_for("print_po", id=id))
        flash("PO updated!", "success")
        return redirect(url_for("po"))
    pd = conn.execute("SELECT * FROM po WHERE id=?", (id,)).fetchone()
    it = conn.execute("SELECT * FROM po_items WHERE po_id=?", (id,)).fetchall()
    pl = conn.execute("SELECT project_name FROM projects").fetchall()
    v = conn.execute("SELECT party_name FROM parties WHERE party_type='Creditor'").fetchall()
    m = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close()
    return render_template("edit_po.html", po=pd, items=it, project_list=pl, vendors=v, materials=m, new_vendor=new_vendor)

@app.route("/po/print/<int:id>")
def print_po(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); p = conn.execute("SELECT * FROM po WHERE id=?", (id,)).fetchone()
    if not p: conn.close(); return redirect(url_for("po"))
    it = conn.execute("SELECT * FROM po_items WHERE po_id=?", (id,)).fetchall()
    v = conn.execute("SELECT * FROM parties WHERE party_name=? AND party_type='Creditor'", (p['vendor_name'],)).fetchone()
    conn.close()
    st = 0; total_gst = 0
    for i in it:
        basic = (float(i['quantity'] or 0) * float(i['rate'] or 0))
        gst = basic * (float(i['gst_rate'] or 18) / 100)
        st += basic; total_gst += gst
    intra = True if v and v['gstin'] and v['gstin'].startswith('33') else False
    return render_template("print_po.html", po=p, items=it, vendor=v,
                           sub_total=st,
                           cgst=(total_gst/2 if intra else 0),
                           sgst=(total_gst/2 if intra else 0),
                           igst=(0 if intra else total_gst),
                           total_gst=total_gst,
                           grand_total=round(st+total_gst, 2),
                           is_intra_state=intra)

# ==========================================
# STOCK (Complete)
# ==========================================
@app.route("/stock", methods=["GET", "POST"])
def stock():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    try:
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
            adj = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Adjustment'", (m['material_name'],)).fetchone()[0] or 0
            av = m['opening_stock'] + rec - iss - adj
            lr = conn.execute("SELECT rate FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt' ORDER BY id DESC LIMIT 1", (m['material_name'],)).fetchone()
            cr = lr[0] if lr else 0
            summary.append({"id": m['id'], "material_code": m['material_code'], "material_name": m['material_name'], "unit": m['unit'], "opening_stock": m['opening_stock'], "received": rec, "issued": iss, "adjusted": adj, "available_stock": av, "current_rate": cr, "reorder_level": m['reorder_level']})

        ledger = conn.execute("SELECT * FROM stock_ledger ORDER BY transaction_date ASC, id ASC").fetchall()
        l_list = []; bal = {}
        for r in ledger:
            mn = r['material_name']
            if mn not in bal:
                md = conn.execute("SELECT opening_stock FROM stock WHERE material_name=?", (mn,)).fetchone()
                bal[mn] = md['opening_stock'] if md else 0
            if r['transaction_type'] == 'Receipt':
                bal[mn] += r['quantity']
            else:
                bal[mn] -= r['quantity']
            l_list.append({"date": r['transaction_date'], "material": mn, "type": r['transaction_type'], "invoice": r['invoice_no'], "project": r['project_name'], "in_qty": r['quantity'] if r['transaction_type']=='Receipt' else 0, "out_qty": r['quantity'] if r['transaction_type'] in ('Issue', 'Adjustment') else 0, "rate": r['rate'], "balance": bal[mn]})

        low = [s for s in summary if s['available_stock'] <= s['reorder_level']]
        pmr = conn.execute("SELECT project_name, material_name, SUM(quantity) as total_issued FROM stock_ledger WHERE transaction_type='Issue' AND project_name != '' GROUP BY project_name, material_name").fetchall()
        pl = conn.execute("SELECT project_name FROM projects").fetchall()
        conn.close()
        return render_template("stock.html", summary_list=summary, ledger_list=l_list, low_stock_list=low, project_material_report=pmr, project_list=pl)
    except Exception as e:
        if conn: conn.close()
        return f"<h2 style='color:red; padding:20px;'>Error Loading Stock:</h2><p style='padding:20px; font-size:18px;'>{str(e)}</p>"

@app.route("/stock_adjustment", methods=["GET", "POST"])
def stock_adjustment():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    try:
        if request.method == "POST":
            mat = request.form.get("material_name")
            qty = float(request.form.get("quantity") or 0)
            adj_date = request.form.get("adjustment_date")
            reason = request.form.get("reason")
            remarks = request.form.get("remarks", "")
            op = conn.execute("SELECT opening_stock FROM stock WHERE material_name=?", (mat,)).fetchone()
            op_stock = op['opening_stock'] if op else 0
            rec = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt'", (mat,)).fetchone()[0] or 0
            iss = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Issue'", (mat,)).fetchone()[0] or 0
            adj = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name=? AND transaction_type='Adjustment'", (mat,)).fetchone()[0] or 0
            avail = op_stock + rec - iss - adj
            if qty > avail:
                flash(f"Stock Error: Only {avail} units available.", "error")
            else:
                cur = conn.cursor()
                rate_row = conn.execute("SELECT rate FROM stock_ledger WHERE material_name=? AND transaction_type='Receipt' ORDER BY id DESC LIMIT 1", (mat,)).fetchone()
                current_rate = rate_row['rate'] if rate_row else 0
                loss_amount = round(qty * current_rate, 2)
                cur.execute("INSERT INTO stock_adjustments (adjustment_date, material_name, quantity, reason, remarks) VALUES (?, ?, ?, ?, ?)", (adj_date, mat, qty, reason, remarks))
                cur.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, 'Adjustment', 'ADJ', 'General', ?, ?)", (mat, adj_date, qty, current_rate))
                if loss_amount > 0:
                    cur.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', 'General', 'Store Loss', 'Adjustment')",
                                (adj_date, f"{reason}: {mat}", loss_amount))
                conn.commit()
                flash("Stock adjusted successfully! Deducted from Inventory & Accounts.", "success")
            conn.close()
            return redirect(url_for("stock_adjustment"))
        materials = conn.execute("""SELECT s.id, s.material_name, s.unit,
            (s.opening_stock + IFNULL((SELECT SUM(quantity) FROM stock_ledger WHERE material_name=s.material_name AND transaction_type='Receipt'),0) - IFNULL((SELECT SUM(quantity) FROM stock_ledger WHERE material_name=s.material_name AND transaction_type='Issue'),0) - IFNULL((SELECT SUM(quantity) FROM stock_ledger WHERE material_name=s.material_name AND transaction_type='Adjustment'),0)) as available_stock
            FROM stock s""").fetchall()
        history = conn.execute("SELECT * FROM stock_adjustments ORDER BY id DESC").fetchall()
        conn.close()
        return render_template("stock_adjustment.html", materials=materials, history=history, today=datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        if conn: conn.close()
        return f"<h2 style='color:red; padding:20px;'>Error in Stock Adjustment:</h2><p style='padding:20px; font-size:18px;'>{str(e)}</p>"

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
            iid = cur.lastrowid
            for i in range(len(request.form.getlist("material_name[]"))):
                mat = request.form.getlist("material_name[]")[i]
                if mat.strip():
                    q = float(request.form.getlist("quantity[]")[i] or 0)
                    r = float(request.form.getlist("rate[]")[i] or 0)
                    cur.execute("INSERT INTO material_issue_items (issue_id, material_name, quantity, rate, amount) VALUES (?, ?, ?, ?, ?)", (iid, mat, q, r, round(q*r, 2)))
                    cur.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, 'Issue', ?, ?, ?, ?)", (mat, issue_date, f"MIN-{iid}", proj, q, r))
            conn.commit()
            flash("Material Issued successfully! (Stock updated)", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("material_issue"))
    issues = conn.execute("SELECT * FROM material_issues ORDER BY id DESC").fetchall()
    pl = conn.execute("SELECT project_name FROM projects").fetchall()
    mats = conn.execute("""SELECT s.material_name, s.unit,
        IFNULL((SELECT rate FROM stock_ledger WHERE material_name = s.material_name AND transaction_type = 'Receipt' ORDER BY id DESC LIMIT 1), 0) as current_rate
        FROM stock s""").fetchall()
    conn.close()
    return render_template("material_issue.html", issue_list=issues, project_list=pl, materials=mats)

@app.route("/material_issue/print/<int:id>")
def print_material_issue(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    issue = conn.execute("SELECT * FROM material_issues WHERE id=?", (id,)).fetchone()
    if not issue:
        flash("Not found!", "error"); conn.close(); return redirect(url_for("material_issue"))
    items = conn.execute("SELECT * FROM material_issue_items WHERE issue_id=?", (id,)).fetchall()
    proj = conn.execute("SELECT * FROM projects WHERE project_name=?", (issue['project_name'],)).fetchone()
    conn.close()
    return render_template("print_material_issue.html", issue=issue, items=items, project=proj)
# ==========================================
# LABOUR & ATTENDANCE
# ==========================================
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
        dt = request.form.get("attendance_date")
        conn.execute("DELETE FROM labour_attendance WHERE attendance_date=?", (dt,))
        for k, v in request.form.items():
            if k.startswith("status_"):
                lid = k.split("_")[1]
                conn.execute("INSERT INTO labour_attendance (labour_id, attendance_date, status, project_name) VALUES (?, ?, ?, ?)", (lid, dt, v, request.form.get(f"project_{lid}", "")))
        conn.commit(); flash("Attendance saved!", "success"); conn.close(); return redirect(url_for("attendance", date=dt))

    l = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    ea = conn.execute("SELECT * FROM labour_attendance WHERE attendance_date=?", (d,)).fetchall()
    # ✅ FIX: Convert sqlite3.Row to dict for safe template access
    ad = {str(a['labour_id']): dict(a) for a in ea}

    category_summary = []
    try:
        cat_query = """
            SELECT COALESCE(l.designation, 'Unknown') as designation, COUNT(*) as count
            FROM labour_attendance la
            JOIN labour l ON la.labour_id = l.id
            WHERE la.attendance_date = ? AND la.status = 'Present'
            GROUP BY l.designation ORDER BY count DESC
        """
        category_summary = conn.execute(cat_query, (d,)).fetchall()
    except Exception as e:
        print("Category summary error:", e)

    conn.close()
    return render_template("attendance.html", labours=l, selected_date=d, att_dict=ad, category_summary=category_summary)

@app.route("/attendance_report")
def attendance_report():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); m = request.args.get("month") or datetime.now().strftime("%Y-%m")
    l = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    rd = []
    for x in l:
        pd = conn.execute("SELECT COUNT(*) FROM labour_attendance WHERE labour_id=? AND status='Present' AND strftime('%Y-%m', attendance_date)=?", (x['id'], m)).fetchone()[0]
        rd.append({"id": x['id'], "name": x['labour_name'], "designation": x['designation'], "wage": x['daily_wage'], "present_days": pd, "total_salary": pd*x['daily_wage'], "project": x['project_name']})
    conn.close()
    return render_template("attendance_report.html", report_data=rd, selected_month=m)

# ==========================================
# ACCOUNTS ENTRY (BILLS + LEDGER)
# ==========================================
@app.route("/accounts_entry", methods=["GET", "POST"])
def accounts_entry():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    sp = request.args.get("project", "") or request.form.get("project_name", "")
    if request.method == "POST" and not sp:
        sp = "General"

    eb_id = request.args.get("edit_bill")
    ea_id = request.args.get("edit_account")

    if request.method == "POST":
        ft = request.form.get("form_type")
        if ft == "bill":
            try:
                cur = conn.cursor()
                desc = request.form.getlist("description[]")
                hsn = request.form.getlist("hsn_sac[]")
                qty = request.form.getlist("quantity[]")
                sr = request.form.getlist("supply_rate[]")
                er = request.form.getlist("erection_rate[]")
                gst = request.form.getlist("gst_rate[]")
                cp_list = request.form.getlist("claim_percentage[]")
                max_len = len(desc)
                def pad_list(lst, length, default='0'):
                    return lst + [default] * (length - len(lst))
                hsn = pad_list(hsn, max_len, '')
                qty = pad_list(qty, max_len, '0')
                sr = pad_list(sr, max_len, '0')
                er = pad_list(er, max_len, '0')
                gst = pad_list(gst, max_len, '18')
                cp_list = pad_list(cp_list, max_len, '100')

                gt = 0; its = []
                for i in range(len(desc)):
                    if desc[i].strip():
                        q = float(qty[i] or 0); s = float(sr[i] or 0); e = float(er[i] or 0)
                        g = float(gst[i] or 0); cp = float(cp_list[i] or 100) if i < len(cp_list) else 100.0
                        full_b = q * (s + e)
                        b = round(full_b * (cp / 100), 2)
                        ga = round(b * (g / 100), 2)
                        ta = round(b + ga, 2)
                        gt += ta
                        its.append({"d": desc[i], "h": hsn[i], "q": q, "s": s, "e": e, "cp": cp, "r": s+e, "g": g, "b": b, "ga": ga, "ta": ta})

                eid = request.form.get("edit_id")
                if eid:
                    cur.execute("DELETE FROM bill_items WHERE bill_id=?", (eid,))

                if request.form.get("bill_no") and its:
                    if eid:
                        cur.execute("UPDATE bills SET bill_no=?, bill_date=?, total_value=?, bill_type=? WHERE id=?", (request.form.get("bill_no"), request.form.get("bill_date"), round(gt), request.form.get("bill_type"), eid))
                        bid = eid
                    else:
                        cur.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value, bill_type) VALUES (?, ?, ?, ?, ?)", (sp, request.form.get("bill_no"), request.form.get("bill_date"), round(gt), request.form.get("bill_type")))
                        bid = cur.lastrowid

                    for it in its:
                        cur.execute("INSERT INTO bill_items (bill_id, description, hsn_sac, quantity, rate, supply_rate, erection_rate, gst_rate, basic_amount, gst_amount, total_amount, claim_percentage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (bid, it["d"], it["h"], it["q"], it["r"], it["s"], it["e"], it["g"], it["b"], it["ga"], it["ta"], it["cp"]))
                        if request.form.get("bill_type") == "BOQ":
                            wp = conn.execute("""SELECT id, qty_supply, qty_erection, billed_qty_supply, billed_qty_erection FROM work_progress
                                WHERE TRIM(project_name)=TRIM(?) AND boq_item_id IN (SELECT id FROM poq WHERE TRIM(material_name)=TRIM(?)) LIMIT 1""",
                                (sp, it["d"])).fetchone()
                            if wp:
                                claimed_qty = it["q"] * (it["cp"] / 100)
                                add_sup = claimed_qty if it["s"] > 0 else 0
                                add_ere = claimed_qty if it["e"] > 0 else 0
                                new_billed_sup = (wp['billed_qty_supply'] or 0) + add_sup
                                new_billed_ere = (wp['billed_qty_erection'] or 0) + add_ere
                                is_sup_done = 1 if new_billed_sup >= wp['qty_supply'] else 0
                                is_ere_done = 1 if new_billed_ere >= wp['qty_erection'] else 0
                                conn.execute("UPDATE work_progress SET billed_qty_supply=?, billed_qty_erection=?, is_billed_supply=?, is_billed_erection=? WHERE id=?", (new_billed_sup, new_billed_ere, is_sup_done, is_ere_done, wp['id']))
                    conn.commit()
                    flash("Bill saved!", "success")
                else:
                    flash("Required fields missing.", "error")
            except Exception as e:
                flash(f"Error: {e}", "error")
            conn.close()
            return redirect(url_for("accounts_entry", project=sp, tab='tab1'))

        elif ft == "ledger":
            try:
                if request.form.get("description"):
                    eid = request.form.get("edit_id")
                    if eid:
                        conn.execute("UPDATE accounts SET transaction_date=?, description=?, amount=?, transaction_type=?, paid_name=?, category=?, bill_no=? WHERE id=?", (request.form.get("transaction_date"), request.form.get("description"), float(request.form.get("amount") or 0), request.form.get("transaction_type"), request.form.get("paid_name"), request.form.get("category"), request.form.get("bill_no"), eid))
                    else:
                        conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category, bill_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (request.form.get("transaction_date"), request.form.get("description"), float(request.form.get("amount") or 0), request.form.get("transaction_type"), sp, request.form.get("paid_name"), request.form.get("category"), request.form.get("bill_no")))
                    conn.commit()
                    flash("Ledger saved!", "success")
                    conn.close()
                    return redirect(url_for("accounts_entry", project=sp, tab='tab2'))
            except Exception as e:
                flash(f"Error: {e}", "error")

    eb_data, eb_items, ea_data = None, [], None
    if eb_id:
        r = conn.execute("SELECT * FROM bills WHERE id=?", (eb_id,)).fetchone()
        if r:
            eb_data = dict(r)
            eb_items = [dict(x) for x in conn.execute("SELECT * FROM bill_items WHERE bill_id=?", (eb_id,)).fetchall()]
    if ea_id:
        r = conn.execute("SELECT * FROM accounts WHERE id=?", (ea_id,)).fetchone()
        if r: ea_data = dict(r)

    at = request.args.get("tab", "tab1")
    if ea_id: at = "tab2"

    today = datetime.now()
    current_year = today.year
    fy_start_year = current_year if today.month >= 4 else current_year - 1
    fy_start = f"{fy_start_year}-04-01"
    fy_end = f"{fy_start_year + 1}-03-31"

    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    pa = conn.execute("SELECT party_name FROM parties ORDER BY party_name").fetchall()

    pd, bl, al, ti, te, cb = None, [], [], 0, 0, 0
    pb = []
    pending_payments, pending_bills, unbilled_work = [], [], []

    bills_query = """
        SELECT b.id, b.project_name, b.bill_no, b.bill_date, b.total_value, b.bill_type,
               IFNULL(SUM(bi.basic_amount), 0) as basic_total,
               IFNULL(SUM(bi.gst_amount), 0) as gst_total
        FROM bills b LEFT JOIN bill_items bi ON b.id = bi.bill_id
    """

    if sp and sp != "General":
        pd = conn.execute("SELECT * FROM projects WHERE TRIM(project_name)=TRIM(?)", (sp,)).fetchone()
        if pd:
            bl = conn.execute(bills_query + " WHERE TRIM(b.project_name)=TRIM(?) GROUP BY b.id ORDER BY b.bill_date DESC", (sp,)).fetchall()
            cb = sum((b['total_value'] or 0) for b in bl)
            al = conn.execute("SELECT * FROM accounts WHERE TRIM(project_name)=TRIM(?) AND transaction_type != 'Credit Note' ORDER BY transaction_date DESC, id DESC", (sp,)).fetchall()
            ti = sum((r['amount'] or 0) for r in al if r['transaction_type'] in ('Income', 'Debit Note'))
            te = sum((r['amount'] or 0) for r in al if r['transaction_type'] == 'Expense')
            pb = conn.execute("""SELECT bq.*,
                MAX(0, bq.quantity - IFNULL((SELECT SUM(qty_supply) FROM work_progress WHERE boq_item_id = bq.id), 0)) as max_sup,
                MAX(0, bq.quantity - IFNULL((SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id = bq.id), 0)) as max_ere
                FROM poq bq WHERE TRIM(bq.project_name)=TRIM(?)""", (sp,)).fetchall()
            pending_payments = conn.execute("SELECT * FROM purchases WHERE TRIM(project_name)=TRIM(?) AND md_approval='Approved' AND payment_status='Pending'", (sp,)).fetchall()
            pending_bills = conn.execute("SELECT bill_no, total_value FROM bills WHERE TRIM(project_name)=TRIM(?) AND bill_no NOT IN (SELECT bill_no FROM accounts WHERE bill_no IS NOT NULL AND TRIM(project_name)=TRIM(?))", (sp, sp)).fetchall()
            unbilled_work = conn.execute("""SELECT wp.id, bq.material_name, wp.qty_supply, wp.qty_erection, bq.supply_rate, bq.erection_rate
                FROM work_progress wp JOIN poq bq ON wp.boq_item_id = bq.id
                WHERE TRIM(wp.project_name) = TRIM(?)
                AND ((wp.qty_supply > IFNULL(wp.billed_qty_supply, 0)) OR (wp.qty_erection > IFNULL(wp.billed_qty_erection, 0)))""", (sp,)).fetchall()
    else:
        if sp == "General":
            bl = conn.execute(bills_query + " WHERE TRIM(b.project_name)='General' GROUP BY b.id ORDER BY b.bill_date DESC").fetchall()
            al = conn.execute("SELECT * FROM accounts WHERE TRIM(project_name)='General' AND transaction_type != 'Credit Note' ORDER BY transaction_date DESC, id DESC").fetchall()
        else:
            bl = conn.execute(bills_query + " GROUP BY b.id ORDER BY b.bill_date DESC").fetchall()
            al = conn.execute("SELECT * FROM accounts WHERE transaction_type != 'Credit Note' ORDER BY transaction_date DESC, id DESC").fetchall()
        cb = sum((b['total_value'] or 0) for b in bl)
        ti = sum((r['amount'] or 0) for r in al if r['transaction_type'] in ('Income', 'Debit Note'))
        te = sum((r['amount'] or 0) for r in al if r['transaction_type'] == 'Expense')

    # ✅ Safety: ensure pb is always list
    pb = pb or []

    conn.close()
    return render_template("entry.html",
                           project_list=pl, selected_project=sp,
                           project_details=pd, bills=bl,
                           accounts=al, total_income=ti,
                           total_expense=te, cumulative_bills=cb,
                           parties_list=pa, project_boq_items=pb,
                           edit_bill_data=eb_data, edit_bill_items=eb_items,
                           edit_account_data=ea_data, active_tab=at,
                           pending_payments=pending_payments, pending_bills=pending_bills,
                           unbilled_work=unbilled_work,
                           fy_start=fy_start, fy_end=fy_end)

@app.route("/pay_purchase_bill/<int:id>", methods=["POST"])
def pay_purchase_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    bill = conn.execute("SELECT * FROM purchases WHERE id=?", (id,)).fetchone()
    if bill and bill['payment_status'] == 'Pending':
        pay_amt = bill['net_payable'] if bill['net_payable'] and bill['net_payable'] > 0 else bill['approved_amount']
        conn.execute("UPDATE purchases SET payment_status='Paid' WHERE id=?", (id,))
        conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', ?, ?, 'Payment')",
                     (datetime.now().strftime("%Y-%m-%d"), f"Payment for Bill {bill['invoice_number']} (After TDS/Retention)", pay_amt, bill['project_name'], bill['supplier_name']))
        conn.commit(); flash("Payment Successful! Net Amount deducted from Accounts.", "success")
    else:
        flash("Invalid or already paid bill.", "error")
    conn.close()
    return redirect(url_for("accounts_entry", project=request.args.get("project", ""), tab="tab2"))

@app.route("/accounts/delete/<int:id>")
def delete_account_entry(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM accounts WHERE id=?", (id,)); conn.commit(); conn.close()
    flash("Deleted!", "success")
    return redirect(url_for("accounts_entry", project=request.args.get("project"), tab=request.args.get("tab", "tab4")))

@app.route("/bills/delete/<int:id>")
def delete_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    bill = conn.execute("SELECT project_name FROM bills WHERE id=?", (id,)).fetchone()
    if not bill:
        flash("Bill not found!", "error"); conn.close(); return redirect(url_for("accounts"))
    project_name = bill['project_name']
    tab = request.args.get("tab", "tab3")
    bill_items = conn.execute("SELECT description, quantity, supply_rate, erection_rate, claim_percentage FROM bill_items WHERE bill_id=?", (id,)).fetchall()
    for item in bill_items:
        mat_name = item['description'].strip()
        qty = item['quantity']
        s_rate = item['supply_rate'] or 0
        e_rate = item['erection_rate'] or 0
        cp = item['claim_percentage'] or 100
        claimed_qty = qty * (cp / 100)
        wp = conn.execute("""SELECT id, billed_qty_supply, billed_qty_erection FROM work_progress
            WHERE TRIM(project_name)=TRIM(?) AND boq_item_id IN (SELECT id FROM poq WHERE TRIM(material_name)=TRIM(?)) LIMIT 1""",
            (project_name, mat_name)).fetchone()
        if wp:
            new_sup = max(0, (wp['billed_qty_supply'] or 0) - claimed_qty) if s_rate > 0 else (wp['billed_qty_supply'] or 0)
            new_ere = max(0, (wp['billed_qty_erection'] or 0) - claimed_qty) if e_rate > 0 else (wp['billed_qty_erection'] or 0)
            conn.execute("""UPDATE work_progress SET billed_qty_supply=?, billed_qty_erection=?, is_billed_supply=0, is_billed_erection=0 WHERE id=?""", (new_sup, new_ere, wp['id']))
    conn.execute("DELETE FROM bill_items WHERE bill_id=?", (id,))
    conn.execute("DELETE FROM bills WHERE id=?", (id,))
    log_activity("Delete Bill", f"Deleted Sales Bill ID: {id}")
    conn.commit(); conn.close()
    flash("Bill deleted successfully! Work Progress unlocked.", "success")
    return redirect(url_for("accounts_entry", project=project_name, tab=tab))

@app.route("/bill/print/<int:id>")
def print_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); b = conn.execute("SELECT * FROM bills WHERE id=?", (id,)).fetchone()
    if not b:
        flash("Not found!", "error"); conn.close(); return redirect(url_for("accounts"))
    items = conn.execute("SELECT * FROM bill_items WHERE bill_id=?", (id,)).fetchall()
    proj = conn.execute("SELECT * FROM projects WHERE project_name=?", (b['project_name'],)).fetchone()
    cli = conn.execute("SELECT * FROM parties WHERE party_name=? AND party_type='Debtor'", (proj['client_name'],)).fetchone() if proj else None
    conn.close()
    et = sum((i['total_amount'] or 0) for i in items); rt = round(et)
    return render_template("print_bill.html", bill=b, items=items, project=proj, client=cli, amount_in_words=num_to_words(rt), rounded_total=rt, round_off=rt-et)

# ==========================================
# CREDIT NOTES
# ==========================================
@app.route("/credit_notes", methods=["GET", "POST"])
def credit_notes():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    sp = request.args.get("project", "") or request.form.get("project_name", "")
    bill_id = request.args.get("bill_id") or request.form.get("bill_id")

    if request.method == "POST":
        try:
            cn_no = request.form.get("cn_no"); cn_date = request.form.get("cn_date")
            desc = request.form.getlist("description[]"); qty = request.form.getlist("quantity[]")
            rate = request.form.getlist("rate[]"); gst = request.form.getlist("gst_rate[]")
            cur = conn.cursor()
            gt = 0; its = []
            for i in range(len(desc)):
                if desc[i].strip():
                    q = float(qty[i] or 0); r = float(rate[i] or 0); g = float(gst[i] or 0)
                    b = round(q*r, 2); ga = round(b*(g/100), 2); ta = round(b+ga, 2)
                    gt += ta
                    its.append({"d": desc[i], "q": q, "r": r, "g": g, "b": b, "ga": ga, "ta": ta})
            if cn_no and sp and bill_id and its:
                proj = conn.execute("SELECT client_name FROM projects WHERE TRIM(project_name)=TRIM(?)", (sp,)).fetchone()
                client_name = proj['client_name'] if proj else "Unknown Client"
                cur.execute("INSERT INTO credit_notes (bill_id, project_name, cn_no, cn_date, total_value) VALUES (?, ?, ?, ?, ?)",
                            (bill_id, sp.strip(), cn_no, cn_date, round(gt, 2)))
                cn_id = cur.lastrowid
                for it in its:
                    cur.execute("INSERT INTO credit_note_items (cn_id, description, quantity, rate, gst_rate, basic_amount, gst_amount, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (cn_id, it["d"], it["q"], it["r"], it["g"], it["b"], it["ga"], it["ta"]))
                    wp = conn.execute("""SELECT id, billed_qty_supply, billed_qty_erection FROM work_progress
                        WHERE TRIM(project_name)=TRIM(?) AND boq_item_id IN (SELECT id FROM poq WHERE TRIM(material_name)=TRIM(?)) LIMIT 1""",
                        (sp, it["d"])).fetchone()
                    if wp:
                        new_sup = max(0, (wp['billed_qty_supply'] or 0) - it["q"])
                        new_ere = max(0, (wp['billed_qty_erection'] or 0) - it["q"])
                        conn.execute("UPDATE work_progress SET billed_qty_supply=?, billed_qty_erection=?, is_billed_supply=0, is_billed_erection=0 WHERE id=?", (new_sup, new_ere, wp['id']))
                cur.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, bill_no) VALUES (?, ?, ?, 'Credit Note', ?, ?, ?)",
                            (cn_date, f"Credit Note {cn_no} for Bill {request.form.get('orig_bill_no')}", round(gt, 2), sp, client_name, cn_no))
                conn.commit()
                flash("Credit Note generated successfully! It will now show in Ledger.", "success")
                conn.close()
                return redirect(url_for("credit_notes", project=sp))
            else:
                flash("Required fields missing!", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("credit_notes", project=sp))

    pl = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
    bills = []; bill_items = []; orig_bill = None
    if sp:
        bills = conn.execute("SELECT * FROM bills WHERE TRIM(project_name)=TRIM(?) ORDER BY id DESC", (sp,)).fetchall()
    if bill_id:
        orig_bill = conn.execute("SELECT * FROM bills WHERE id=?", (bill_id,)).fetchone()
        bill_items = conn.execute("SELECT * FROM bill_items WHERE bill_id=?", (bill_id,)).fetchall()
    cn_history = conn.execute("SELECT * FROM credit_notes ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("credit_notes.html", project_list=pl, selected_project=sp, bill_list=bills, selected_bill=orig_bill, bill_items=bill_items, cn_history=cn_history, today=datetime.now().strftime("%Y-%m-%d"))

@app.route("/credit_notes/delete/<int:id>")
def delete_credit_note(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    cn = conn.execute("SELECT * FROM credit_notes WHERE id=?", (id,)).fetchone()
    if not cn:
        flash("Credit Note not found!", "error"); conn.close(); return redirect(url_for("credit_notes"))
    project_name = cn['project_name']; cn_no = cn['cn_no']
    try:
        cn_items = conn.execute("SELECT * FROM credit_note_items WHERE cn_id=?", (id,)).fetchall()
        for item in cn_items:
            mat_name = item['description'].strip(); qty = item['quantity']
            wp = conn.execute("""SELECT id, billed_qty_supply, billed_qty_erection FROM work_progress
                WHERE TRIM(project_name)=TRIM(?) AND boq_item_id IN (SELECT id FROM poq WHERE TRIM(material_name)=TRIM(?)) LIMIT 1""",
                (project_name, mat_name)).fetchone()
            if wp:
                new_sup = (wp['billed_qty_supply'] or 0) + qty
                new_ere = (wp['billed_qty_erection'] or 0) + qty
                conn.execute("UPDATE work_progress SET billed_qty_supply=?, billed_qty_erection=? WHERE id=?", (new_sup, new_ere, wp['id']))
        conn.execute("DELETE FROM accounts WHERE transaction_type='Credit Note' AND bill_no=?", (cn_no,))
        conn.execute("DELETE FROM credit_note_items WHERE cn_id=?", (id,))
        conn.execute("DELETE FROM credit_notes WHERE id=?", (id,))
        conn.commit()
        flash("Credit Note deleted successfully and Work Progress restored!", "success")
    except Exception as e:
        flash(f"Error deleting CN: {e}", "error")
    conn.close()
    return redirect(url_for("credit_notes", project=project_name))

# ==========================================
# ACCOUNTS OVERVIEW
# ==========================================
@app.route("/accounts")
def accounts():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    today = datetime.now()
    fy_start_year = today.year if today.month >= 4 else today.year - 1
    default_start = f"{fy_start_year}-04-01"
    default_end = f"{fy_start_year + 1}-03-31"
    start_date = request.args.get("start_date") or default_start
    end_date = request.args.get("end_date") or default_end

    ap = conn.execute("SELECT * FROM projects").fetchall()
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    pnl = []
    for p in ap:
        sales = conn.execute("""SELECT SUM(bi.basic_amount) FROM bill_items bi
            JOIN bills b ON bi.bill_id = b.id
            WHERE TRIM(b.project_name) = TRIM(?) AND b.bill_date BETWEEN ? AND ?""",
            (p['project_name'], start_date, end_date)).fetchone()[0] or 0
        income = conn.execute("""SELECT SUM(amount) FROM accounts
            WHERE (TRIM(project_name)=TRIM(?) OR (TRIM(project_name)='General' AND TRIM(paid_name)=TRIM(?)))
            AND transaction_type IN ('Receipt', 'Bank Receipt')
            AND transaction_date BETWEEN ? AND ?""",
            (p['project_name'], p['client_name'], start_date, end_date)).fetchone()[0] or 0
        expense = conn.execute("""SELECT SUM(amount) FROM accounts
            WHERE project_name=? AND transaction_type = 'Expense'
            AND transaction_date BETWEEN ? AND ?""",
            (p['project_name'], start_date, end_date)).fetchone()[0] or 0
        profit = sales - expense
        pnl.append({"id": p['id'], "project_name": p['project_name'], "client": p['client_name'], "value": p['project_value'], "sales": sales, "income": income, "expense": expense, "profit": profit})
    conn.close()
    return render_template("accounts.html", pnl_list=pnl, project_list=pl, start_date=start_date, end_date=end_date)

@app.route("/general_expenses", methods=["GET", "POST"])
def general_expenses():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    today = datetime.now()
    default_start = today.strftime("%Y-%m-01")
    default_end = today.strftime("%Y-%m-%d")
    start_date = request.args.get("start_date") or default_start
    end_date = request.args.get("end_date") or default_end

    if request.method == "POST":
        try:
            date = request.form.get("date"); desc = request.form.get("description")
            amount = float(request.form.get("amount") or 0)
            paid_name = request.form.get("paid_name"); category = request.form.get("category")
            if date and desc and amount > 0:
                conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', 'General', ?, ?)",
                             (date, desc, amount, paid_name, category))
                conn.commit()
                flash("General Expense recorded successfully!", "success")
            else:
                flash("Required fields missing!", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("general_expenses", start_date=start_date, end_date=end_date))

    expenses = conn.execute("""SELECT * FROM accounts
        WHERE project_name = 'General' AND transaction_type = 'Expense'
        AND transaction_date BETWEEN ? AND ?
        ORDER BY transaction_date DESC, id DESC""", (start_date, end_date)).fetchall()
    conn.close()
    return render_template("general_expenses.html", expenses=expenses, today=today.strftime("%Y-%m-%d"), start_date=start_date, end_date=end_date)
# ==========================================
# COMPANY P&L
# ==========================================
@app.route("/company_pnl")
def company_pnl():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    today = datetime.now()
    fy_start_year = today.year if today.month >= 4 else today.year - 1
    default_start = f"{fy_start_year}-04-01"
    default_end = f"{fy_start_year + 1}-03-31"
    start_date = request.args.get("start_date") or default_start
    end_date = request.args.get("end_date") or default_end

    gross_sales = conn.execute("""SELECT SUM(bi.basic_amount) FROM bill_items bi
        JOIN bills b ON bi.bill_id = b.id
        WHERE b.bill_date BETWEEN ? AND ?""", (start_date, end_date)).fetchone()[0] or 0
    cn_amount = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Credit Note' AND transaction_date BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0] or 0
    net_sales = gross_sales - cn_amount
    project_expenses = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Expense' AND project_name != 'General' AND transaction_date BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0] or 0
    cogs_list = conn.execute("""SELECT category, SUM(amount) as total FROM accounts
        WHERE transaction_type = 'Expense' AND project_name != 'General' AND transaction_date BETWEEN ? AND ?
        GROUP BY category""", (start_date, end_date)).fetchall()
    general_expenses = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Expense' AND project_name = 'General' AND transaction_date BETWEEN ? AND ?", (start_date, end_date)).fetchone()[0] or 0
    net_profit = net_sales - project_expenses - general_expenses
    exp_list = conn.execute("""SELECT category, SUM(amount) as total FROM accounts
        WHERE project_name = 'General' AND transaction_type = 'Expense' AND transaction_date BETWEEN ? AND ?
        GROUP BY category""", (start_date, end_date)).fetchall()
    sales_gst = conn.execute("""SELECT SUM(bi.gst_amount) FROM bill_items bi
        JOIN bills b ON bi.bill_id = b.id WHERE b.bill_date BETWEEN ? AND ?""", (start_date, end_date)).fetchone()[0] or 0
    purchase_gst = conn.execute("""SELECT SUM(pi.quantity * pi.rate * (pi.gst_rate / 100.0)) FROM purchase_items pi
        JOIN purchases p ON pi.purchase_id = p.id
        WHERE p.invoice_date BETWEEN ? AND ? AND p.md_approval = 'Approved'""", (start_date, end_date)).fetchone()[0] or 0
    conn.close()
    return render_template("company_pnl.html",
                           gross_sales=gross_sales, cn_amount=cn_amount, net_sales=net_sales,
                           project_expenses=project_expenses, cogs_list=cogs_list,
                           general_expenses=general_expenses, net_profit=net_profit,
                           exp_list=exp_list, start_date=start_date, end_date=end_date,
                           sales_gst=sales_gst, purchase_gst=purchase_gst)

# ==========================================
# PROJECT P&L (with None check fix)
# ==========================================
@app.route("/project_pnl/<project_name>")
def project_pnl_detail(project_name):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    # ✅ FIX: Handle None project
    p = conn.execute("SELECT * FROM projects WHERE TRIM(project_name)=TRIM(?)", (project_name,)).fetchone()
    if not p:
        flash("Project not found!", "error")
        conn.close()
        return redirect(url_for("dashboard"))
    tx = conn.execute("""SELECT * FROM accounts
        WHERE (TRIM(project_name)=TRIM(?) OR (TRIM(project_name)='General' AND TRIM(paid_name)=TRIM(?)))
        AND transaction_type IN ('Receipt', 'Payment', 'Bank Receipt', 'Bank Payment')
        ORDER BY transaction_date ASC, id ASC""", (project_name, p['client_name'])).fetchall()
    conn.close()
    ti = sum(t['amount'] for t in tx if 'receipt' in t['transaction_type'].lower())
    te = sum(t['amount'] for t in tx if 'payment' in t['transaction_type'].lower())
    net_profit = ti - te
    return render_template("project_pnl_detail.html", project=p, transactions=tx, total_inflow=ti, total_outflow=te, net_profit=net_profit)

# ==========================================
# COST CONTROL
# ==========================================
@app.route("/cost_control/<project_name>")
def cost_control(project_name):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE project_name=?", (project_name,)).fetchone()
    if not project:
        flash("Project not found!", "error")
        conn.close()
        return redirect(url_for("dashboard"))
    boq_items = conn.execute("SELECT * FROM poq WHERE project_name=?", (project_name,)).fetchall()
    total_actual_pur_all = conn.execute("""SELECT SUM(pi.quantity * pi.rate) FROM purchase_items pi
        JOIN purchases p ON pi.purchase_id = p.id
        WHERE p.project_name = ? AND p.md_approval = 'Approved'""", (project_name,)).fetchone()[0] or 0
    total_other_exp = conn.execute("""SELECT SUM(amount) FROM accounts
        WHERE project_name=? AND transaction_type = 'Expense'
        AND IFNULL(category, '') NOT IN ('Payment', 'M', 'Credit Note', 'Debit Note', 'Purchase')""",
        (project_name,)).fetchone()[0] or 0
    cost_data = []; t_plan=0; t_pur=0; t_fore=0; t_client=0; t_item_profit=0

    if not boq_items:
        total_client_value = project['project_value'] or 0
        total_projected_cost = total_actual_pur_all + total_other_exp
        final_net_profit = total_client_value - total_projected_cost
        conn.close()
        return render_template("cost_control.html",
                               project=project, cost_data=[],
                               total_plan_cost=0, total_actual_pur=total_actual_pur_all,
                               total_other_exp=total_other_exp, total_forecast_cost=0,
                               total_client_value=total_client_value,
                               total_projected_cost=total_projected_cost,
                               total_item_profit=0, final_net_profit=final_net_profit)

    for item in boq_items:
        item_dict = dict(item)
        qty = item_dict.get('quantity') or 0
        c_sup = item_dict.get('company_supply_rate') or 0
        c_ere = item_dict.get('company_erection_rate') or 0
        plan = qty * (c_sup + c_ere)
        pur = conn.execute("""SELECT SUM(pi.quantity * pi.rate) FROM purchase_items pi
            JOIN purchases p ON pi.purchase_id = p.id
            WHERE p.project_name = ? AND LOWER(TRIM(pi.material_name)) = LOWER(TRIM(?))""",
            (project_name, item_dict['material_name'])).fetchone()[0] or 0
        pur_qty = conn.execute("""SELECT SUM(pi.quantity) FROM purchase_items pi
            JOIN purchases p ON pi.purchase_id = p.id
            WHERE p.project_name = ? AND LOWER(TRIM(pi.material_name)) = LOWER(TRIM(?))""",
            (project_name, item_dict['material_name'])).fetchone()[0] or 0
        issued_qty = conn.execute("""SELECT SUM(mii.quantity) FROM material_issue_items mii
            JOIN material_issues mi ON mii.issue_id = mi.id
            WHERE mi.project_name = ? AND LOWER(TRIM(mii.material_name)) = LOWER(TRIM(?))""",
            (project_name, item_dict['material_name'])).fetchone()[0] or 0
        stock_qty = pur_qty - issued_qty
        done_ere = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id=?", (item_dict['id'],)).fetchone()[0] or 0
        forecast_sup = max(0, (qty * c_sup) - pur)
        forecast_ere = max(0, qty - done_ere) * c_ere
        fore = forecast_sup + forecast_ere
        cli_val = qty * ((item_dict.get('supply_rate') or 0) + (item_dict.get('erection_rate') or 0))
        item_total_cost = pur + fore
        item_profit = cli_val - item_total_cost
        cost_data.append({"description": item_dict['material_name'], "qty": qty, "client_value": cli_val, "plan_cost": plan, "actual_pur": pur, "forecast_cost": fore, "total_projected_cost": item_total_cost, "projected_profit": item_profit, "pur_qty": pur_qty, "issued_qty": issued_qty, "stock_qty": stock_qty})
        t_plan += plan; t_pur += pur; t_fore += fore; t_client += cli_val; t_item_profit += item_profit

    final_net_profit = t_item_profit - total_other_exp
    conn.close()
    return render_template("cost_control.html",
                           project=project, cost_data=cost_data,
                           total_plan_cost=t_plan, total_actual_pur=t_pur,
                           total_other_exp=total_other_exp,
                           total_forecast_cost=t_fore, total_client_value=t_client,
                           total_projected_cost=t_pur+t_fore,
                           total_item_profit=t_item_profit, final_net_profit=final_net_profit)

# ==========================================
# PARTIES
# ==========================================
@app.route("/parties", methods=["GET", "POST"])
def parties():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        try:
            party_name = request.form.get("party_name", "").strip()
            gstin = request.form.get("gstin", "").strip()
            if party_name and gstin:
                existing = conn.execute("SELECT id FROM parties WHERE party_name=? OR gstin=?", (party_name, gstin)).fetchone()
                if existing:
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'status': 'error', 'message': 'Party already exists!'})
                    flash("Exists!", "error")
                else:
                    conn.execute("INSERT INTO parties (party_name, party_type, contact_number, email, gstin, address, opening_balance) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                 (party_name, request.form.get("party_type"), request.form.get("contact_number"), request.form.get("email"), gstin, request.form.get("address"), float(request.form.get("opening_balance") or 0)))
                    conn.commit()
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'status': 'success', 'message': 'Party created successfully!'})
                    flash("Party created!", "success")
            else:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'status': 'error', 'message': 'Name & GSTIN required.'})
                flash("Name & GSTIN required.", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
    p_list = conn.execute("SELECT * FROM parties ORDER BY id DESC").fetchall()
    conn.close()
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
        else:
            flash("Name/GSTIN conflict!", "error")
    p = conn.execute("SELECT * FROM parties WHERE id=?", (id,)).fetchone(); conn.close()
    return render_template("edit_party.html", party=p)

@app.route("/parties/toggle_block/<int:id>")
def toggle_block_party(id):
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "Admin", "GM"]:
        flash("Only MD/Admin/GM can block a party.", "error")
        return redirect(url_for("parties"))
    conn = get_db()
    party = conn.execute("SELECT is_blocked, party_name FROM parties WHERE id=?", (id,)).fetchone()
    if party:
        new_status = 0 if party['is_blocked'] == 1 else 1
        conn.execute("UPDATE parties SET is_blocked=? WHERE id=?", (new_status, id))
        conn.commit()
        status_text = "Blocked 🚫" if new_status == 1 else "Unblocked ✅"
        flash(f"Party '{party['party_name']}' is now {status_text}.", "success")
    conn.close()
    return redirect(url_for("parties"))

# ==========================================
# CLIENT & VENDOR LEDGER
# ==========================================
@app.route("/client_ledger")
def client_ledger():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    clients = conn.execute("""SELECT DISTINCT paid_name as name FROM accounts WHERE transaction_type IN ('Receipt', 'Credit Note', 'Income') AND paid_name!=''
        UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type='Debtor'
        UNION SELECT DISTINCT client_name as name FROM projects""").fetchall()
    sc = request.args.get("client", "")
    start_date = request.args.get("start_date") or datetime.now().strftime("%Y-04-01")
    end_date = request.args.get("end_date") or datetime.now().strftime("%Y-%m-%d")
    tx = []; ob=0; td=0; tc=0; cb=0
    if sc:
        p = conn.execute("SELECT opening_balance FROM parties WHERE TRIM(party_name)=TRIM(?) AND party_type='Debtor'", (sc,)).fetchone()
        base_ob = p['opening_balance'] if p else 0
        past_bills = conn.execute("""SELECT SUM(total_value) FROM bills
            WHERE project_name IN (SELECT project_name FROM accounts WHERE TRIM(paid_name)=TRIM(?) AND transaction_type='Income')
            AND bill_date < ?""", (sc, start_date)).fetchone()[0] or 0
        past_payments = conn.execute("""SELECT SUM(amount) FROM accounts
            WHERE transaction_type IN ('Receipt', 'Credit Note') AND TRIM(paid_name)=TRIM(?) AND transaction_date < ?""",
            (sc, start_date)).fetchone()[0] or 0
        ob = base_ob + past_bills - past_payments
        b = conn.execute("""SELECT bill_date as date, 'Bill (Inv: ' || bill_no || ')' as particulars, total_value as debit, 0 as credit
            FROM bills
            WHERE project_name IN (SELECT project_name FROM accounts WHERE TRIM(paid_name)=TRIM(?) AND transaction_type='Income')
            AND bill_date >= ? AND bill_date <= ?""", (sc, start_date, end_date)).fetchall()
        pay = conn.execute("""SELECT transaction_date as date, 'By ' || description as particulars, 0 as debit, amount as credit
            FROM accounts
            WHERE transaction_type IN ('Credit Note', 'Receipt', 'Bank Receipt') AND TRIM(paid_name)=TRIM(?)
            AND transaction_date >= ? AND transaction_date <= ?""", (sc, start_date, end_date)).fetchall()
        raw = [dict(x) for x in b] + [dict(x) for x in pay]
        raw.sort(key=lambda x: x['date'] if x['date'] else '9999')
        rb = ob; td = ob; tc = 0
        for r in raw:
            d = r['debit'] or 0; c = r['credit'] or 0
            td += d; tc += c; rb += d-c
            r['balance'] = rb; tx.append(r)
        cb = rb
    conn.close()
    return render_template("client_ledger.html", clients=clients, transactions=tx, selected_client=sc, opening_balance=ob, total_debit=td, total_credit=tc, closing_balance=cb, start_date=start_date, end_date=end_date)

@app.route("/vendor_ledger")
def vendor_ledger():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    v = conn.execute("SELECT DISTINCT supplier_name as name FROM purchases UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type='Creditor'").fetchall()
    sv = request.args.get("vendor", "")
    start_date = request.args.get("start_date") or datetime.now().strftime("%Y-04-01")
    end_date = request.args.get("end_date") or datetime.now().strftime("%Y-%m-%d")
    tx = []; ob=0; tpo=0; tb=0; tp=0; cb=0
    if sv:
        p = conn.execute("SELECT opening_balance FROM parties WHERE party_name=? AND party_type='Creditor'", (sv,)).fetchone()
        if p: ob = p['opening_balance']
        po = conn.execute("""SELECT po.id, po.po_date as date, 'PO #' || po.id as particulars, 'PO' as type,
            IFNULL(SUM(po_items.quantity*po_items.rate),0)*1.18 as po_value, 0 as bill_value, 0 as paid_amount
            FROM po JOIN po_items ON po.id=po_items.po_id
            WHERE po.vendor_name=? AND po.po_date >= ? AND po.po_date <= ? GROUP BY po.id""",
            (sv, start_date, end_date)).fetchall()
        b = conn.execute("""SELECT id, invoice_date as date, 'Bill' as particulars, 'Bill' as type,
            0 as po_value, total_amount as bill_value, 0 as paid_amount
            FROM purchases WHERE supplier_name=? AND invoice_date >= ? AND invoice_date <= ?""",
            (sv, start_date, end_date)).fetchall()
        pay = conn.execute("""SELECT id, transaction_date as date, 'Payment' as particulars, 'Payment' as type,
            0 as po_value, 0 as bill_value, amount as paid_amount
            FROM accounts WHERE transaction_type IN ('Debit Note', 'Payment', 'Bank Payment') AND paid_name=?
            AND transaction_date >= ? AND transaction_date <= ?""",
            (sv, start_date, end_date)).fetchall()
        raw = [dict(x) for x in po] + [dict(x) for x in b] + [dict(x) for x in pay]
        raw.sort(key=lambda x: x['date'] if x['date'] else '9999')
        rb = ob
        for r in raw:
            if r['type'] != 'PO': rb += (r['bill_value'] or 0) - (r['paid_amount'] or 0)
            r['balance'] = rb
            if r['type']=='PO': tpo += r['po_value'] or 0
            elif r['type']=='Bill': tb += r['bill_value'] or 0
            elif r['type']=='Payment': tp += r['paid_amount'] or 0
            tx.append(r)
        cb = rb
    conn.close()
    return render_template("vendor_ledger.html", vendors=v, transactions=tx, selected_vendor=sv, opening_balance=ob, total_po_value=tpo, total_bill_value=tb, total_paid=tp, closing_balance=cb, po_bill_diff=tpo-tb, start_date=start_date, end_date=end_date)

# ==========================================
# BOQ & WORK PROGRESS
# ==========================================
@app.route("/poq", methods=["GET", "POST"])
def poq():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); sp = request.args.get("project", ""); eid = request.args.get("edit")
    if request.method == "POST":
        sp = request.form.get("project_name", ""); eid = request.form.get("edit_id")
        try:
            desc = request.form.getlist("item_description[]")
            units = request.form.getlist("unit[]")
            qtys = request.form.getlist("quantity[]")
            act_qtys = request.form.getlist("actual_quantity[]")
            srs = request.form.getlist("supply_rate[]")
            ers = request.form.getlist("erection_rate[]")
            csrs = request.form.getlist("comp_supply_rate[]")
            cers = request.form.getlist("comp_erection_rate[]")
            subs = request.form.getlist("subcon_name[]")
            subrs = request.form.getlist("subcon_rate[]")
            for i in range(len(desc)):
                if desc[i].strip():
                    q = float(qtys[i] or 0)
                    aq = float(act_qtys[i] or 0) if i < len(act_qtys) and act_qtys[i] else q
                    sr = float(srs[i] or 0); er = float(ers[i] or 0)
                    csr = float(csrs[i] or 0); cer = float(cers[i] or 0)
                    sn = subs[i].strip() if i < len(subs) and subs[i] else ""
                    scr = float(subrs[i] or 0); u = units[i]
                    tr = sr + er; amt = round(aq * tr, 2)
                    if eid:
                        conn.execute("""UPDATE poq SET
                            material_name=?, unit=?, quantity=?, actual_quantity=?,
                            rate=?, amount=?, supply_rate=?, erection_rate=?,
                            company_supply_rate=?, company_erection_rate=?,
                            subcon_name=?, subcon_rate=? WHERE id=?""",
                            (desc[i], u, q, aq, tr, amt, sr, er, csr, cer, sn, scr, eid))
                        flash("Updated!", "success"); eid = None
                    else:
                        conn.execute("""INSERT INTO poq
                            (project_name, material_name, unit, quantity, actual_quantity, rate, amount, supply_rate, erection_rate, company_supply_rate, company_erection_rate, subcon_name, subcon_rate)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (sp, desc[i], u, q, aq, tr, amt, sr, er, csr, cer, sn, scr))
                        if not conn.execute("SELECT id FROM stock WHERE material_name=?", (desc[i],)).fetchone():
                            conn.execute("INSERT INTO stock (material_name, unit, opening_stock) VALUES (?, ?, 0)", (desc[i], u))
            conn.commit(); flash("Saved!", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("poq", project=sp))
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall(); bl = []; tb=0; ebd = None
    if eid: ebd = conn.execute("SELECT * FROM poq WHERE id=?", (eid,)).fetchone()
    if sp:
        bl = conn.execute("SELECT * FROM poq WHERE project_name=? ORDER BY id ASC", (sp,)).fetchall()
        tb = sum((x['amount'] or 0) for x in bl)
    conn.close()
    return render_template("poq.html", project_list=pl, selected_project=sp, boq_list=bl, total_boq_value=tb, edit_boq_data=ebd)

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
        bid = request.form.get("boq_item_id")
        qs = float(request.form.get("qty_supply") or 0)
        qe = float(request.form.get("qty_erection") or 0)
        if bid and (qs > 0 or qe > 0):
            conn.execute("INSERT INTO work_progress (project_name, boq_item_id, work_date, qty_supply, qty_erection, remarks) VALUES (?, ?, ?, ?, ?, ?)", (sp, bid, request.form.get("work_date"), qs, qe, request.form.get("remarks", "")))
            conn.commit(); flash("Updated!", "success")
        conn.close(); return redirect(url_for("work_progress", project=sp))
    pl = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall(); bpl = []; wh = []
    if sp:
        for i in conn.execute("SELECT * FROM poq WHERE project_name=? ORDER BY id ASC", (sp,)).fetchall():
            ds = conn.execute("SELECT SUM(qty_supply) FROM work_progress WHERE boq_item_id=?", (i['id'],)).fetchone()[0] or 0
            de = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id=?", (i['id'],)).fetchone()[0] or 0
            total_boq_qty = i['actual_quantity'] if i['actual_quantity'] is not None else (i['quantity'] or 0)
            bpl.append({"id": i['id'], "description": i['material_name'], "unit": i['unit'], "total_qty": total_boq_qty, "done_supply": ds, "done_erection": de, "balance_supply": total_boq_qty - ds, "balance_erection": total_boq_qty - de, "supply_rate": i['supply_rate'] or 0, "erection_rate": i['erection_rate'] or 0})
        wh = [dict(r) for r in conn.execute("""SELECT wp.id, wp.work_date, bq.material_name, wp.qty_supply, wp.qty_erection, wp.remarks,
            wp.is_billed_supply, wp.is_billed_erection, wp.billed_qty_supply, wp.billed_qty_erection
            FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id
            WHERE wp.project_name=? ORDER BY wp.work_date DESC, wp.id DESC""", (sp,)).fetchall()]
    conn.close()
    return render_template("work_progress.html", project_list=pl, selected_project=sp, boq_progress_list=bpl, work_history=wh)

@app.route("/work_progress/delete/<int:id>")
def delete_work_progress(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); wp = conn.execute("SELECT * FROM work_progress WHERE id=?", (id,)).fetchone()
    if wp:
        if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1:
            flash("Cannot delete billed work.", "error")
        else:
            conn.execute("DELETE FROM work_progress WHERE id=?", (id,)); conn.commit(); flash("Deleted!", "success")
    conn.close(); return redirect(url_for("work_progress", project=request.args.get("project", "")))

@app.route("/work_progress/edit/<int:id>", methods=["GET", "POST"])
def edit_work_progress(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); wp = conn.execute("SELECT * FROM work_progress WHERE id=?", (id,)).fetchone()
    if not wp:
        flash("Not found!", "error"); conn.close(); return redirect(url_for("work_progress"))
    if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1:
        flash("Cannot edit billed work.", "error"); conn.close(); return redirect(url_for("work_progress", project=wp['project_name']))
    if request.method == "POST":
        conn.execute("UPDATE work_progress SET work_date=?, qty_supply=?, qty_erection=?, remarks=? WHERE id=?", (request.form.get("work_date"), float(request.form.get("qty_supply") or 0), float(request.form.get("qty_erection") or 0), request.form.get("remarks"), id))
        conn.commit(); conn.close(); flash("Updated!", "success"); return redirect(url_for("work_progress", project=wp['project_name']))
    bq = conn.execute("SELECT * FROM poq WHERE id=?", (wp['boq_item_id'],)).fetchone(); conn.close()
    return render_template("edit_work_progress.html", wp=wp, boq_item=bq)

# ==========================================
# SUBCONTRACTOR BILLING
# ==========================================
@app.route("/subcon", methods=["GET", "POST"])
def subcon():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    sp = request.args.get("project", "")
    if request.method == "POST":
        sp = request.form.get("project_name")
        subcon_name = request.form.get("subcon_name")
        bill_date = request.form.get("bill_date")
        remarks = request.form.get("remarks", "")
        mat_deduction = float(request.form.get("material_deduction") or 0)
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO subcon_bills (project_name, subcon_name, bill_date, remarks, material_deduction) VALUES (?, ?, ?, ?, ?)", (sp, subcon_name, bill_date, remarks, mat_deduction))
            bill_id = cur.lastrowid
            boq_ids = request.form.getlist("boq_item_id[]"); qtys = request.form.getlist("quantity[]"); rates = request.form.getlist("rate[]")
            total_amt = 0
            for i in range(len(boq_ids)):
                q = float(qtys[i] or 0)
                if q > 0:
                    r = float(rates[i] or 0); amt = round(q * r, 2); total_amt += amt
                    cur.execute("INSERT INTO subcon_bill_items (bill_id, boq_item_id, quantity, rate, amount) VALUES (?, ?, ?, ?, ?)", (bill_id, boq_ids[i], q, r, amt))
            net_payable = total_amt - mat_deduction
            cur.execute("UPDATE subcon_bills SET total_amount=? WHERE id=?", (net_payable, bill_id))
            if net_payable > 0:
                cur.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, 'Expense', ?, ?, 'Subcon')",
                            (bill_date, f"Subcon Bill (Work: {total_amt}, Less Mat: {mat_deduction})", net_payable, sp, subcon_name))
            conn.commit()
            flash("Subcon Bill generated successfully with Material Deduction!", "success")
        except Exception as e:
            flash(f"Error: {e}", "error")
        conn.close()
        return redirect(url_for("subcon", project=sp))
    project_list = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
    vendors = conn.execute("SELECT party_name FROM parties WHERE party_type='Creditor' ORDER BY party_name").fetchall()
    subcon_items = []
    if sp:
        subcon_items = conn.execute("""SELECT * FROM poq
            WHERE TRIM(project_name)=TRIM(?) AND subcon_name IS NOT NULL AND subcon_name != ''""", (sp,)).fetchall()
    history = conn.execute("SELECT * FROM subcon_bills WHERE TRIM(project_name)=TRIM(?) ORDER BY id DESC", (sp,)).fetchall() if sp else []
    mat_issues = conn.execute("""SELECT mi.issued_to, mii.material_name, mii.quantity, mii.rate, mii.amount
        FROM material_issues mi JOIN material_issue_items mii ON mi.id = mii.issue_id
        WHERE mi.project_name = ? AND mi.issued_to IS NOT NULL AND mi.issued_to != ''""", (sp,)).fetchall()
    issues_dict = {}
    for row in mat_issues:
        sc = row['issued_to']
        if sc not in issues_dict: issues_dict[sc] = []
        issues_dict[sc].append(dict(row))
    conn.close()
    today = datetime.now().strftime("%Y-%m-%d")
    return render_template("subcon.html", project_list=project_list, selected_project=sp, subcon_items=subcon_items, vendors=vendors, history=history, today=today, issues_dict=issues_dict)

@app.route("/subcon/print/<int:id>")
def print_subcon_bill(id):
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    bill = conn.execute("SELECT * FROM subcon_bills WHERE id=?", (id,)).fetchone()
    if not bill:
        flash("Not found", "error"); conn.close(); return redirect(url_for("subcon"))
    items = conn.execute("""SELECT sbi.*, bq.material_name, bq.unit
        FROM subcon_bill_items sbi JOIN poq bq ON sbi.boq_item_id = bq.id
        WHERE sbi.bill_id=?""", (id,)).fetchall()
    project = conn.execute("SELECT * FROM projects WHERE TRIM(project_name)=TRIM(?)", (bill['project_name'],)).fetchone()
    conn.close()
    return render_template("print_subcon.html", bill=bill, items=items, project=project)

# ==========================================
# GST REPORTS
# ==========================================
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
                if not {'Invoice Number', 'Trade/Legal Name', 'Total'}.issubset(df.columns):
                    flash("Invalid Excel Columns!", "error")
                else:
                    for _, r in df.iterrows():
                        conn.execute("INSERT INTO gstr2b_data (supplier_name, invoice_number, total_value) VALUES (?, ?, ?)", (str(r.get('Trade/Legal Name')), str(r.get('Invoice Number')), float(r.get('Total', 0))))
                    conn.commit(); flash("Uploaded! Click Reconcile.", "success")
            except Exception as e:
                flash(f"Error: {e}", "error")
        conn.close(); return redirect(url_for("gst_reconciliation"))
    ud = conn.execute("SELECT * FROM gstr2b_data ORDER BY id DESC").fetchall(); conn.close()
    return render_template("gst_reconciliation.html", uploaded_data=ud)

@app.route("/gst_reports", methods=["GET"])
def gst_reports():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    selected_month = request.args.get("month") or datetime.now().strftime("%Y-%m")
    output_data = conn.execute("""SELECT SUM(bi.basic_amount) as taxable_value, SUM(bi.gst_amount) as total_tax
        FROM bill_items bi JOIN bills b ON bi.bill_id = b.id
        WHERE strftime('%Y-%m', b.bill_date) = ?""", (selected_month,)).fetchone()
    taxable_sales = output_data['taxable_value'] or 0
    output_tax = output_data['total_tax'] or 0
    input_data = conn.execute("""SELECT SUM(pi.quantity * pi.rate * (pi.gst_rate / 100)) as input_tax
        FROM purchase_items pi JOIN purchases p ON pi.purchase_id = p.id
        WHERE strftime('%Y-%m', p.invoice_date) = ? AND p.md_approval = 'Approved'""", (selected_month,)).fetchone()
    input_tax = input_data['input_tax'] or 0
    net_tax = output_tax - input_tax
    hsn_data = conn.execute("""SELECT COALESCE(NULLIF(TRIM(bi.hsn_sac), ''), 'No HSN') as hsn,
        SUM(bi.quantity) as total_qty, SUM(bi.basic_amount) as taxable_value, SUM(bi.gst_amount) as tax_amount
        FROM bill_items bi JOIN bills b ON bi.bill_id = b.id
        WHERE strftime('%Y-%m', b.bill_date) = ? GROUP BY bi.hsn_sac""", (selected_month,)).fetchall()
    conn.close()
    return render_template("gst_reports.html", selected_month=selected_month, taxable_sales=taxable_sales, output_tax=output_tax, input_tax=input_tax, net_tax=net_tax, hsn_data=hsn_data)

@app.route("/gstr1")
def gstr1():
    if not session.get("username"): return redirect(url_for("login"))
    selected_month = request.args.get("month") or datetime.now().strftime("%Y-%m")
    return render_template("gstr1.html", selected_month=selected_month)

def get_state_name(code):
    states = {"33": "Tamil Nadu", "29": "Karnataka", "32": "Kerala", "36": "Telangana", "37": "Andhra Pradesh"}
    return states.get(str(code), "Unknown")

@app.route("/gstr1/export")
def gstr1_export():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") == "Site Supervisor": return redirect(url_for("dashboard"))
    selected_month = request.args.get("month")
    if not selected_month:
        flash("Please select a month!", "error"); return redirect(url_for("gstr1"))
    conn = get_db()
    query = """SELECT b.bill_no, b.bill_date, pr.client_name, p.gstin as client_gstin,
        bi.description, bi.hsn_sac, bi.quantity, bi.rate as gst_rate, bi.basic_amount, bi.gst_amount
        FROM bills b JOIN projects pr ON b.project_name = pr.project_name
        LEFT JOIN parties p ON pr.client_name = p.party_name AND p.party_type = 'Debtor'
        JOIN bill_items bi ON b.id = bi.bill_id
        WHERE strftime('%Y-%m', b.bill_date) = ?"""
    bills_data = conn.execute(query, (selected_month,)).fetchall()
    conn.close()
    if not bills_data:
        flash(f"No sales bills found for the month {selected_month}.", "warning"); return redirect(url_for("gstr1"))
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["GSTIN/UIN of Recipient", "Receiver Name", "Invoice Number", "Invoice date", "Invoice Value", "Place Of Supply", "Reverse Charge", "Applicable % of Tax Rate", "Invoice Type", "E-Commerce GSTIN", "Rate", "Taxable Value", "Cess Amount", "CGST", "SGST", "IGST"])
    for row in bills_data:
        gstin = row['client_gstin'] if row['client_gstin'] else ""
        state_code = gstin[:2] if gstin else "33"
        pos = f"{state_code}-{get_state_name(state_code)}"
        is_intra = True if state_code == "33" else False
        total_gst = row['gst_amount'] or 0
        cgst = total_gst / 2 if is_intra else 0
        sgst = total_gst / 2 if is_intra else 0
        igst = 0 if is_intra else total_gst
        inv_type = "Regular B2B" if gstin else "Regular B2C"
        writer.writerow([gstin, row['client_name'], row['bill_no'], row['bill_date'], (row['basic_amount'] or 0) + (row['gst_amount'] or 0), pos, "N", "", inv_type, "", row['gst_rate'] or 0, row['basic_amount'] or 0, 0, round(cgst, 2), round(sgst, 2), round(igst, 2)])
    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(csv_bytes, mimetype="text/csv", as_attachment=True, download_name=f"GSTR1_{selected_month}.csv")

@app.route("/run_reconciliation")
def run_reconciliation():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    for row in conn.execute("SELECT * FROM gstr2b_data").fetchall():
        p = conn.execute("SELECT total_amount FROM purchases WHERE invoice_number=? AND TRIM(supplier_name)=TRIM(?)", (row['invoice_number'], row['supplier_name'])).fetchone()
        if p:
            if abs((p['total_amount'] or 0)-(row['total_value'] or 0)) < 0.01:
                conn.execute("UPDATE gstr2b_data SET match_status='Matched' WHERE id=?", (row['id'],))
            else:
                conn.execute("UPDATE gstr2b_data SET match_status='Amount Mismatch' WHERE id=?", (row['id'],))
        else:
            conn.execute("UPDATE gstr2b_data SET match_status='Missing in Purchase' WHERE id=?", (row['id'],))
    conn.commit(); conn.close()
    flash("Reconciliation Completed!", "success")
    return redirect(url_for("gst_reconciliation"))

@app.route("/clear_gstr2b")
def clear_gstr2b():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db(); conn.execute("DELETE FROM gstr2b_data"); conn.commit(); conn.close()
    flash("GSTR-2B data cleared!", "success")
    return redirect(url_for("gst_reconciliation"))

# ==========================================
# REPORTS
# ==========================================
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

# ==========================================
# AGING REPORT
# ==========================================
@app.route("/aging_report")
def aging_report():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    today = datetime.now()
    fy_start_year = today.year if today.month >= 4 else today.year - 1
    start_date = request.args.get("start_date") or f"{fy_start_year}-04-01"
    end_date = request.args.get("end_date") or f"{fy_start_year + 1}-03-31"
    clients = conn.execute("SELECT DISTINCT party_name FROM parties WHERE party_type='Debtor' ORDER BY party_name").fetchall()
    report_data = []
    grand_totals = {"b_30": 0, "b_60": 0, "b_90": 0, "b_over": 0, "total": 0}
    for c in clients:
        client_name = c['party_name']
        p = conn.execute("SELECT opening_balance FROM parties WHERE TRIM(party_name)=TRIM(?)", (client_name,)).fetchone()
        party_ob = p['opening_balance'] if p else 0
        pre_bills = conn.execute("SELECT SUM(b.total_value) FROM bills b JOIN projects pr ON TRIM(b.project_name)=TRIM(pr.project_name) WHERE TRIM(pr.client_name)=TRIM(?) AND b.bill_date < ?", (client_name, start_date)).fetchone()[0] or 0
        pre_pays = conn.execute("SELECT SUM(amount) FROM accounts WHERE TRIM(paid_name)=TRIM(?) AND transaction_type IN ('Income', 'Credit Note') AND transaction_date < ?", (client_name, start_date)).fetchone()[0] or 0
        opening_balance = party_ob + pre_bills - pre_pays
        period_payments = conn.execute("SELECT SUM(amount) FROM accounts WHERE TRIM(paid_name)=TRIM(?) AND transaction_type IN ('Income', 'Credit Note') AND transaction_date >= ? AND transaction_date <= ?", (client_name, start_date, end_date)).fetchone()[0] or 0
        bills = conn.execute("""SELECT b.* FROM bills b JOIN projects pr ON TRIM(b.project_name)=TRIM(pr.project_name)
            WHERE TRIM(pr.client_name) = TRIM(?) AND b.bill_date >= ? AND b.bill_date <= ?
            ORDER BY b.bill_date ASC, b.id ASC""", (client_name, start_date, end_date)).fetchall()
        fifo_list = []
        if opening_balance > 0:
            fifo_list.append({"date": start_date, "amount": opening_balance, "is_ob": True})
        for b in bills:
            fifo_list.append({"date": b['bill_date'], "amount": b['total_value'] or 0, "is_ob": False})
        available_payment = period_payments + (abs(opening_balance) if opening_balance < 0 else 0)
        client_buckets = {"b_30": 0, "b_60": 0, "b_90": 0, "b_over": 0}
        client_total = 0
        for item in fifo_list:
            bill_amt = item['amount']; outstanding = bill_amt
            if available_payment > 0:
                if available_payment >= bill_amt:
                    outstanding = 0; available_payment -= bill_amt
                else:
                    outstanding = bill_amt - available_payment; available_payment = 0
            if outstanding > 0.01:
                if item['is_ob']:
                    age_days = 999
                else:
                    try: age_days = (today - datetime.strptime(item['date'], '%Y-%m-%d')).days
                    except: age_days = 0
                if age_days <= 30: client_buckets["b_30"] += outstanding
                elif age_days <= 60: client_buckets["b_60"] += outstanding
                elif age_days <= 90: client_buckets["b_90"] += outstanding
                else: client_buckets["b_over"] += outstanding
                client_total += outstanding
        if client_total > 0.01:
            report_data.append({"client": client_name, "b_30": client_buckets["b_30"], "b_60": client_buckets["b_60"], "b_90": client_buckets["b_90"], "b_over": client_buckets["b_over"], "total": client_total})
            grand_totals["b_30"] += client_buckets["b_30"]; grand_totals["b_60"] += client_buckets["b_60"]
            grand_totals["b_90"] += client_buckets["b_90"]; grand_totals["b_over"] += client_buckets["b_over"]
            grand_totals["total"] += client_total
    report_data.sort(key=lambda x: x['total'], reverse=True)
    conn.close()
    return render_template("aging_report.html", report_data=report_data, grand_totals=grand_totals, start_date=start_date, end_date=end_date, today=today.strftime('%d-%m-%Y'))

# ==========================================
# DEPT PERFORMANCE & DAILY REPORT
# ==========================================
@app.route("/dept_performance")
def dept_performance():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    today = datetime.now()
    start_date = request.args.get("start_date") or today.strftime("%Y-%m-01")
    end_date = request.args.get("end_date") or today.strftime("%Y-%m-%d")
    d = {}
    d['bd_leads'] = conn.execute("SELECT COUNT(*) FROM leads WHERE lead_date >= ? AND lead_date <= ?", (start_date, end_date)).fetchone()[0]
    d['bd_won'] = conn.execute("SELECT COUNT(*) FROM leads WHERE status IN ('Won', 'Converted to Tender') AND lead_date >= ? AND lead_date <= ?", (start_date, end_date)).fetchone()[0]
    d['proc_po'] = conn.execute("SELECT COUNT(*) FROM po WHERE po_date >= ? AND po_date <= ?", (start_date, end_date)).fetchone()[0]
    d['proc_bills'] = conn.execute("SELECT COUNT(*) FROM purchases WHERE invoice_date >= ? AND invoice_date <= ?", (start_date, end_date)).fetchone()[0]
    d['proc_val'] = conn.execute("SELECT SUM(total_amount) FROM purchases WHERE invoice_date >= ? AND invoice_date <= ?", (start_date, end_date)).fetchone()[0] or 0
    d['ops_work_val'] = conn.execute("SELECT SUM(wp.qty_supply * bq.supply_rate) FROM work_progress wp JOIN poq bq ON wp.boq_item_id=bq.id WHERE wp.work_date >= ? AND wp.work_date <= ?", (start_date, end_date)).fetchone()[0] or 0
    d['ops_bills'] = conn.execute("SELECT COUNT(*) FROM bills WHERE bill_date >= ? AND bill_date <= ?", (start_date, end_date)).fetchone()[0]
    d['ops_bill_val'] = conn.execute("SELECT SUM(total_value) FROM bills WHERE bill_date >= ? AND bill_date <= ?", (start_date, end_date)).fetchone()[0] or 0
    d['fin_in'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Income', 'Debit Note') AND transaction_date >= ? AND transaction_date <= ?", (start_date, end_date)).fetchone()[0] or 0
    d['fin_out'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Expense' AND transaction_date >= ? AND transaction_date <= ?", (start_date, end_date)).fetchone()[0] or 0
    d['hr_labour_days'] = conn.execute("SELECT COUNT(*) FROM labour_attendance WHERE status='Present' AND attendance_date >= ? AND attendance_date <= ?", (start_date, end_date)).fetchone()[0]
    conn.close()
    return render_template("dept_performance.html", d=d, start_date=start_date, end_date=end_date)

@app.route("/daily_report")
def daily_report():
    if not session.get("username"): return redirect(url_for("login"))
    conn = get_db()
    selected_date = request.args.get("date") or datetime.now().strftime("%Y-%m-%d")
    d = {}
    d['income'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Income', 'Debit Note') AND transaction_date = ?", (selected_date,)).fetchone()[0] or 0
    d['expense'] = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type IN ('Expense', 'Credit Note') AND transaction_date = ?", (selected_date,)).fetchone()[0] or 0
    d['transactions'] = conn.execute("SELECT * FROM accounts WHERE transaction_date = ? ORDER BY id DESC", (selected_date,)).fetchall()
    d['work_progress'] = conn.execute("""SELECT wp.*, bq.material_name FROM work_progress wp
        JOIN poq bq ON wp.boq_item_id = bq.id
        WHERE wp.work_date = ? ORDER BY wp.id DESC""", (selected_date,)).fetchall()
    d['labour_present'] = conn.execute("SELECT COUNT(*) FROM labour_attendance WHERE status='Present' AND attendance_date = ?", (selected_date,)).fetchone()[0]
    d['material_issues'] = conn.execute("SELECT * FROM material_issues WHERE issue_date = ? ORDER BY id DESC", (selected_date,)).fetchall()
    d['new_purchases'] = conn.execute("SELECT * FROM purchases WHERE invoice_date = ? ORDER BY id DESC", (selected_date,)).fetchall()
    d['new_leads'] = conn.execute("SELECT * FROM leads WHERE lead_date = ? ORDER BY id DESC", (selected_date,)).fetchall()
    conn.close()
    return render_template("daily_report.html", d=d, selected_date=selected_date)

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
    if sp:
        pairs = conn.execute("SELECT DISTINCT project_name, vendor_name FROM po WHERE project_name=? UNION SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases WHERE project_name=?", (sp, sp)).fetchall()
    else:
        pairs = conn.execute("SELECT DISTINCT project_name, vendor_name FROM po UNION SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases").fetchall()
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

# ==========================================
# IMPORT MASTER (TALLY)
# ==========================================
@app.route("/import_master", methods=["GET", "POST"])
def import_master():
    if not session.get("username"): return redirect(url_for("login"))
    if session.get("role") not in ["MD", "Admin", "Accountant"]: return redirect(url_for("dashboard"))
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == '':
            flash("No file selected!", "error"); return redirect(url_for("import_master"))
        try:
            # ✅ Removed duplicate 'import pandas as pd' (already at top)
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            else:
                df = pd.read_excel(file)
            df.columns = df.columns.str.strip()
            conn = get_db(); cur = conn.cursor(); count = 0
            for index, row in df.iterrows():
                try:
                    t_date = pd.to_datetime(row['Date'], dayfirst=True).strftime('%Y-%m-%d')
                    raw_basic = str(row.get('Amount (Basic)', row.get('Amount', '0'))).replace(',', '').strip()
                    basic_amt = float(raw_basic) if raw_basic and raw_basic.lower() != 'nan' else 0.0
                    gst_amt = 0.0
                    gst_col_name = None
                    for col in df.columns:
                        if 'gst' in col.lower() or 'tax' in col.lower():
                            gst_col_name = col; break
                    if gst_col_name and pd.notna(row[gst_col_name]):
                        raw_gst = str(row[gst_col_name]).replace(',', '').strip()
                        if raw_gst and raw_gst.lower() != 'nan':
                            gst_amt = round(float(raw_gst), 2)
                    total_amt = basic_amt + gst_amt
                    t_type_raw = str(row['Type']).strip().lower()
                    if t_type_raw == 'credit note':
                        t_type = 'Credit Note'
                    else:
                        t_type = t_type_raw.capitalize()
                    party = str(row['Party Name']).strip()
                    category = str(row['Category']).strip()
                    proj_name = str(row.get('Project Name', 'General')).strip()
                    if pd.isna(row.get('Project Name')) or proj_name.lower() == 'nan' or not proj_name:
                        proj_name = 'General'
                    inv_no = ''
                    if 'Invoice / Bill No' in df.columns and pd.notna(row['Invoice / Bill No']):
                        inv_no = str(row['Invoice / Bill No']).strip()
                    elif 'Invoice No' in df.columns and pd.notna(row['Invoice No']):
                        inv_no = str(row['Invoice No']).strip()
                    if inv_no.lower() == 'nan':
                        inv_no = ''
                    if not inv_no:
                        inv_no = f"AUTO-{index}"
                    if t_type not in ['Income', 'Expense', 'Payment', 'Receipt', 'Credit Note']:
                        continue
                    if not party or not category: continue
                    if proj_name != 'General':
                        existing_proj = conn.execute("SELECT id FROM projects WHERE TRIM(project_name)=TRIM(?)", (proj_name,)).fetchone()
                        if not existing_proj:
                            conn.execute("INSERT INTO projects (project_name, client_name) VALUES (?, ?)", (proj_name, party))
                    existing_party = conn.execute("SELECT id FROM parties WHERE TRIM(party_name)=TRIM(?)", (party,)).fetchone()
                    if not existing_party:
                        p_type = 'Debtor' if t_type in ['Income', 'Receipt', 'Credit Note'] else 'Creditor'
                        conn.execute("INSERT INTO parties (party_name, party_type) VALUES (?, ?)", (party, p_type))
                    conn.execute("""INSERT INTO accounts
                        (transaction_date, description, amount, transaction_type, project_name, paid_name, category, bill_no)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (t_date, f"Tally Import - {category}", basic_amt, t_type, proj_name, party, category, inv_no))
                    if t_type == 'Income' and category.lower() == 'sales':
                        cur.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value, bill_type) VALUES (?, ?, ?, ?, 'Tally')", (proj_name, inv_no, t_date, total_amt))
                        bid = cur.lastrowid
                        calc_gst_rate = (gst_amt / basic_amt * 100) if basic_amt > 0 else 0
                        cur.execute("""INSERT INTO bill_items
                            (bill_id, description, quantity, rate, gst_rate, basic_amount, gst_amount, total_amount)
                            VALUES (?, 'Imported Sales', 1, ?, ?, ?, ?, ?)""",
                            (bid, basic_amt, calc_gst_rate, basic_amt, gst_amt, total_amt))
                    elif t_type == 'Expense' and category.lower() in ['purchase', 'labour purchase', 'legal purchase']:
                        cur.execute("""INSERT INTO purchases
                            (po_number, project_name, supplier_name, invoice_number, invoice_date, subtotal, gst_amount, total_amount, md_approval, payment_status)
                            VALUES ('Tally', ?, ?, ?, ?, ?, ?, ?, 'Approved', 'Paid')""",
                            (proj_name, party, inv_no, t_date, basic_amt, gst_amt, total_amt))
                        pid = cur.lastrowid
                        calc_gst_rate = (gst_amt / basic_amt * 100) if basic_amt > 0 else 0
                        cur.execute("""INSERT INTO purchase_items
                            (purchase_id, material_name, quantity, rate, gst_rate, amount)
                            VALUES (?, 'Imported Purchase', 1, ?, ?, ?)""",
                            (pid, basic_amt, calc_gst_rate, total_amt))
                    elif t_type == 'Credit Note':
                        cur.execute("""INSERT INTO credit_notes (bill_id, project_name, cn_no, cn_date, total_value)
                            VALUES (0, ?, ?, ?, ?)""", (proj_name, inv_no, t_date, total_amt))
                        cn_id = cur.lastrowid
                        calc_gst_rate = (gst_amt / basic_amt * 100) if basic_amt > 0 else 0
                        cur.execute("""INSERT INTO credit_note_items
                            (cn_id, description, quantity, rate, gst_rate, basic_amount, gst_amount, total_amount)
                            VALUES (?, 'Imported Credit Note', 1, ?, ?, ?, ?, ?)""",
                            (cn_id, basic_amt, calc_gst_rate, basic_amt, gst_amt, total_amt))
                    count += 1
                except Exception as row_e:
                    print(f"Skipping row {index}: {row_e}")
                    continue
            conn.commit(); conn.close()
            flash(f"Successfully imported {count} records with Basic & GST!", "success")
        except Exception as e:
            flash(f"Error reading file: {e}", "error")
        return redirect(url_for("import_master"))
    return render_template("import_master.html")

# ==========================================
# ERROR HANDLERS, INIT & STARTUP
# ==========================================
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return "⚠️ Something went wrong. Please contact admin.", 500

# Initialize DB after all routes are defined
init_db()

if __name__ == "__main__":
    print("--------------------------------")
    print("GOMS ELECTRICALS PVT LTD ERP")
    print("--------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
