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
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "goms-local-development-key-change-before-deployment"
)

# FIX: warn when running with the dev fallback secret
if not os.environ.get("FLASK_SECRET_KEY"):
    print("WARNING: Using default Flask secret key. Set FLASK_SECRET_KEY before deploying!")

app.permanent_session_lifetime = timedelta(minutes=30)


# ------------------------------------------------------------------
# TEMPLATE FILTERS
# ------------------------------------------------------------------
@app.template_filter('dateformat')
def dateformat(value, format='%d/%m/%Y'):
    if not value:
        return "-"
    try:
        return datetime.strptime(value, '%Y-%m-%d').strftime(format)
    except (ValueError, TypeError):
        return value


@app.template_filter('inr')
def format_inr(number):
    if number is None:
        return "0.00"
    try:
        number = float(number)
    except (ValueError, TypeError):
        return "0.00"

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
        if remaining:
            groups.insert(0, remaining)

        formatted_integer = ",".join(groups) + "," + last_three
    else:
        formatted_integer = integer_part

    result = formatted_integer + "." + decimal_part
    if is_negative:
        result = "-" + result
    return result


def num_to_words(num):
    units = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]

    def two_digit(n):
        if n < 20:
            return units[n]
        return tens[n // 10] + (" " + units[n % 10] if n % 10 != 0 else "")

    def three_digit(n):
        if n < 100:
            return two_digit(n)
        return units[n // 100] + " Hundred" + (" and " + two_digit(n % 100) if n % 100 != 0 else "")

    parts = f"{num:.2f}".split(".")
    rupees = int(parts[0])
    paise = int(parts[1])

    words = ""
    if rupees == 0:
        words = "Zero"
    else:
        if rupees >= 10000000:
            words += two_digit(rupees // 10000000) + " Crore "
            rupees %= 10000000
        if rupees >= 100000:
            words += two_digit(rupees // 100000) + " Lakh "
            rupees %= 100000
        if rupees >= 1000:
            words += two_digit(rupees // 1000) + " Thousand "
            rupees %= 1000
        if rupees > 0:
            words += three_digit(rupees)

    words = "Rupees " + words.strip()
    if paise > 0:
        words += " and " + two_digit(paise) + " Paise"
    return words + " Only."


# ------------------------------------------------------------------
# AUTH HELPERS
# ------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000
    ).hex()
    return salt, password_hash


def verify_password(password, salt, expected_hash):
    _, actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------
# DATABASE INIT
# ------------------------------------------------------------------
def init_db():
    conn = get_db()

    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'Admin')")
    conn.execute("CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, client_name TEXT NOT NULL, work_order TEXT, project_value REAL DEFAULT 0, start_date TEXT, status TEXT DEFAULT 'Planning')")
    conn.execute("""CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, po_number TEXT, project_name TEXT NOT NULL, supplier_name TEXT NOT NULL,
        invoice_number TEXT NOT NULL, invoice_date TEXT, material_description TEXT, quantity REAL DEFAULT 0,
        rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, subtotal REAL DEFAULT 0, gst_amount REAL DEFAULT 0,
        total_amount REAL DEFAULT 0, md_approval TEXT DEFAULT 'Pending'
    )""")
    conn.execute("CREATE TABLE IF NOT EXISTS purchase_items (id INTEGER PRIMARY KEY AUTOINCREMENT, purchase_id INTEGER NOT NULL, material_name TEXT, description TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS stock (id INTEGER PRIMARY KEY AUTOINCREMENT, material_code TEXT, material_name TEXT NOT NULL, unit TEXT, opening_stock REAL DEFAULT 0, stock_in REAL DEFAULT 0, stock_out REAL DEFAULT 0, reorder_level REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS stock_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, material_name TEXT NOT NULL, transaction_date TEXT, transaction_type TEXT NOT NULL, invoice_no TEXT, project_name TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS labour (id INTEGER PRIMARY KEY AUTOINCREMENT, labour_name TEXT NOT NULL, designation TEXT, daily_wage REAL DEFAULT 0, contact_number TEXT, join_date TEXT, project_name TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS labour_attendance (id INTEGER PRIMARY KEY AUTOINCREMENT, labour_id INTEGER NOT NULL, attendance_date TEXT NOT NULL, status TEXT NOT NULL, project_name TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, transaction_date TEXT, description TEXT NOT NULL, amount REAL DEFAULT 0, transaction_type TEXT NOT NULL, project_name TEXT, paid_name TEXT, category TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS bills (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, bill_no TEXT NOT NULL, bill_date TEXT, total_value REAL DEFAULT 0)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bill_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL, description TEXT NOT NULL, hsn_sac TEXT,
        quantity REAL DEFAULT 0, rate REAL DEFAULT 0, gst_rate REAL DEFAULT 0, basic_amount REAL DEFAULT 0,
        gst_amount REAL DEFAULT 0, total_amount REAL DEFAULT 0
    )""")
    conn.execute("CREATE TABLE IF NOT EXISTS parties (id INTEGER PRIMARY KEY AUTOINCREMENT, party_name TEXT NOT NULL, party_type TEXT NOT NULL, contact_number TEXT, email TEXT, gstin TEXT, address TEXT, opening_balance REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS poq (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, material_name TEXT NOT NULL, unit TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0, req_date TEXT, status TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS po (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, vendor_name TEXT NOT NULL, po_date TEXT, delivery_address TEXT, quotation_no TEXT, status TEXT DEFAULT 'Ordered', gm_approval TEXT DEFAULT 'Pending')")
    conn.execute("CREATE TABLE IF NOT EXISTS po_items (id INTEGER PRIMARY KEY AUTOINCREMENT, po_id INTEGER NOT NULL, material_name TEXT NOT NULL, hsn_code TEXT, quantity REAL DEFAULT 0, unit TEXT, rate REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS material_issues (id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, issue_date TEXT, issued_to TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS material_issue_items (id INTEGER PRIMARY KEY AUTOINCREMENT, issue_id INTEGER NOT NULL, material_name TEXT NOT NULL, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0)")
    conn.execute("""CREATE TABLE IF NOT EXISTS work_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL, boq_item_id INTEGER NOT NULL,
        work_date TEXT, qty_done REAL DEFAULT 0, remarks TEXT, is_billed INTEGER DEFAULT 0
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS gstr2b_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT, supplier_gstin TEXT, supplier_name TEXT, invoice_number TEXT,
        invoice_date TEXT, total_value REAL DEFAULT 0, match_status TEXT DEFAULT 'Unmatched'
    )""")
    conn.execute("CREATE TABLE IF NOT EXISTS tenders (id INTEGER PRIMARY KEY AUTOINCREMENT, tender_no TEXT NOT NULL, client_name TEXT NOT NULL, tender_date TEXT, submission_date TEXT, status TEXT DEFAULT 'Pending', estimated_value REAL DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS tender_items (id INTEGER PRIMARY KEY AUTOINCREMENT, tender_id INTEGER NOT NULL, description TEXT, unit TEXT, quantity REAL DEFAULT 0, rate REAL DEFAULT 0, amount REAL DEFAULT 0)")

    conn.commit()

    def add_column(table, column, col_type):
        try:
            cursor = conn.execute(f"PRAGMA table_info({table})")
            columns = [info[1] for info in cursor.fetchall()]
            if column not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                conn.commit()
        except Exception:
            pass

    add_column("purchases", "md_approval", "TEXT DEFAULT 'Pending'")
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
    add_column("work_progress", "qty_supply", "REAL DEFAULT 0")
    add_column("work_progress", "qty_erection", "REAL DEFAULT 0")
    add_column("work_progress", "is_billed_supply", "INTEGER DEFAULT 0")
    add_column("work_progress", "is_billed_erection", "INTEGER DEFAULT 0")
    add_column("bill_items", "supply_rate", "REAL DEFAULT 0")
    add_column("bill_items", "erection_rate", "REAL DEFAULT 0")
    add_column("bills", "bill_type", "TEXT DEFAULT 'BOQ'")
    add_column("po", "gm_approval", "TEXT DEFAULT 'Pending'")

    # ============================================================
    # PERFORMANCE INDEXES
    # ============================================================
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_purchases_project   ON purchases(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_purchases_supplier  ON purchases(supplier_name)",
        "CREATE INDEX IF NOT EXISTS idx_purchases_invoice   ON purchases(invoice_number)",
        "CREATE INDEX IF NOT EXISTS idx_purchases_date      ON purchases(invoice_date)",
        "CREATE INDEX IF NOT EXISTS idx_purchase_items_pid  ON purchase_items(purchase_id)",

        "CREATE INDEX IF NOT EXISTS idx_bills_project       ON bills(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_bills_bill_no       ON bills(bill_no)",
        "CREATE INDEX IF NOT EXISTS idx_bills_date          ON bills(bill_date)",
        "CREATE INDEX IF NOT EXISTS idx_bill_items_bid      ON bill_items(bill_id)",

        "CREATE INDEX IF NOT EXISTS idx_accounts_project    ON accounts(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_accounts_type       ON accounts(transaction_type)",
        "CREATE INDEX IF NOT EXISTS idx_accounts_paid_name  ON accounts(paid_name)",
        "CREATE INDEX IF NOT EXISTS idx_accounts_date       ON accounts(transaction_date)",

        "CREATE INDEX IF NOT EXISTS idx_stock_ledger_mat    ON stock_ledger(material_name)",
        "CREATE INDEX IF NOT EXISTS idx_stock_ledger_proj   ON stock_ledger(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_stock_ledger_type   ON stock_ledger(transaction_type)",

        "CREATE INDEX IF NOT EXISTS idx_po_vendor           ON po(vendor_name)",
        "CREATE INDEX IF NOT EXISTS idx_po_project          ON po(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_po_items_po         ON po_items(po_id)",

        "CREATE INDEX IF NOT EXISTS idx_poq_project         ON poq(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_poq_material        ON poq(material_name)",

        "CREATE INDEX IF NOT EXISTS idx_labour_att_lid      ON labour_attendance(labour_id)",
        "CREATE INDEX IF NOT EXISTS idx_labour_att_date     ON labour_attendance(attendance_date)",

        "CREATE INDEX IF NOT EXISTS idx_wp_project          ON work_progress(project_name)",
        "CREATE INDEX IF NOT EXISTS idx_wp_boq              ON work_progress(boq_item_id)",

        "CREATE INDEX IF NOT EXISTS idx_mii_issue           ON material_issue_items(issue_id)",
        "CREATE INDEX IF NOT EXISTS idx_ti_tender           ON tender_items(tender_id)",
    ]
    for idx_sql in indexes:
        try:
            conn.execute(idx_sql)
        except Exception as e:
            print(f"Index skipped: {e}")
    conn.commit()

    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        salt, password_hash = hash_password("ChangeMe@123")
        conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)", ("admin", salt, password_hash, "Admin"))
        conn.commit()

    conn.close()


# ------------------------------------------------------------------
# ACCESS CONTROL
# ------------------------------------------------------------------
@app.before_request
def restrict_site_supervisor():
    if not session.get("username"):
        return

    if session.get("role") == "Site Supervisor":
        blocked_endpoints = [
            'accounts', 'accounts_entry', 'delete_account_entry', 'delete_bill',
            'print_bill', 'client_ledger', 'vendor_ledger', 'parties',
            'delete_party', 'edit_party', 'users', 'delete_user',
            'edit_user_role', 'backup', 'md_approval', 'md_approve',
            'gst_reconciliation', 'run_reconciliation', 'vendor_report',
            'purchases', 'edit_purchase', 'delete_purchase', 'gm_approval', 'gm_approve',
            'po', 'edit_po', 'print_po', 'poq', 'delete_poq',
            'tenders', 'tender_items', 'convert_tender', 'update_tender_status',
            'reports', 'reports_export_csv'
        ]
        if request.endpoint in blocked_endpoints:
            flash("Access Denied: You don't have permission to view this page.", "error")
            return redirect(url_for('dashboard'))
@app.after_request
def add_header(response):
    """
    Prevent the browser from caching authenticated pages.
    Forces the browser to re-request the page from the server.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return "<h2 style='color:#c00;padding:20px;'>404 - Page Not Found</h2><p style='padding:20px;'>The page you requested does not exist.</p>", 404

@app.errorhandler(500)
def internal_error(e):
    return "<h2 style='color:#c00;padding:20px;'>Internal Server Error</h2><p style='padding:20px;'>An unexpected error occurred. Please try again.</p>", 500


# ------------------------------------------------------------------
# GST API
# ------------------------------------------------------------------
@app.route('/api/get-gst-details', methods=['POST'])
def get_gst_details():
    if not session.get("username"):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or {}
    gstin = (data.get('gstin') or '').strip().upper()

    if not gstin or len(gstin) != 15:
        return jsonify({'error': 'Invalid GSTIN length'}), 400

    API_KEY = os.environ.get("GST_API_KEY", "")
    if not API_KEY:
        return jsonify({'error': 'GST API not configured on server'}), 500

    api_url = f"https://sheet.gstincheck.co.in/check/{API_KEY}/{gstin}"

    try:
        response = requests.get(api_url, timeout=10)
        res_data = response.json()

        if res_data.get('flag'):
            details = res_data.get('data', {})
            legal_name = details.get('lgnm', '')
            trade_name = details.get('tradeNam', '')

            addr_obj = details.get('pradr', {}).get('addr', {})
            if isinstance(addr_obj, dict):
                address_parts = [
                    addr_obj.get('bno', ''),
                    addr_obj.get('flno', ''),
                    addr_obj.get('st', ''),
                    addr_obj.get('loc', ''),
                    addr_obj.get('dst', ''),
                    addr_obj.get('stcd', ''),
                    addr_obj.get('pncd', '')
                ]
                address = ", ".join([str(part) for part in address_parts if part])
            else:
                address = str(addr_obj)

            final_name = trade_name if trade_name else legal_name

            return jsonify({
                'legal_name': final_name,
                'address': address
            })
        else:
            return jsonify({'error': 'GST details not found'}), 404

    except Exception as e:
        print(f"GST API Error: {e}")
        return jsonify({'error': 'Failed to fetch GST details'}), 500


# ------------------------------------------------------------------
# AUTH ROUTES
# ------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user:
            if verify_password(password, user["salt"], user["password_hash"]):
                session.permanent = True
                session["username"] = user["username"]
                session["role"] = user["role"] if "role" in user.keys() else "Admin"
                return redirect(url_for("dashboard"))
            else:
                error = "Invalid password."
        else:
            error = "Username not found."

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    try: total_projects = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    except: total_projects = 0
    try: total_project_value = conn.execute("SELECT SUM(project_value) FROM projects").fetchone()[0] or 0
    except: total_project_value = 0
    try: total_sales = conn.execute("SELECT SUM(total_value) FROM bills").fetchone()[0] or 0
    except: total_sales = 0
    try: total_labour = conn.execute("SELECT COUNT(*) FROM labour").fetchone()[0]
    except: total_labour = 0

    try:
        total_income = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Income'").fetchone()[0] or 0
        total_expense = conn.execute("SELECT SUM(amount) FROM accounts WHERE transaction_type = 'Expense'").fetchone()[0] or 0
    except:
        total_income, total_expense = 0, 0

    try:
        low_stock_count = conn.execute("SELECT COUNT(*) FROM stock WHERE opening_stock <= reorder_level").fetchone()[0]
    except:
        low_stock_count = 0

    try:
        pending_approvals = conn.execute("SELECT COUNT(*) FROM purchases WHERE md_approval = 'Pending'").fetchone()[0]
    except:
        pending_approvals = 0

    try:
        pending_gm_approvals = conn.execute("SELECT COUNT(*) FROM po WHERE gm_approval = 'Pending'").fetchone()[0]
    except:
        pending_gm_approvals = 0

    recent_bills = conn.execute("SELECT * FROM bills ORDER BY id DESC LIMIT 5").fetchall()

    # NEW: project status breakdown for pie chart
    try:
        project_statuses = conn.execute("""
            SELECT COALESCE(status, 'Unknown') as status, COUNT(*) as count
            FROM projects GROUP BY status
        """).fetchall()
        status_labels = [row['status'] for row in project_statuses]
        status_counts = [row['count'] for row in project_statuses]
    except Exception:
        status_labels, status_counts = [], []

    conn.close()

    # Indian Financial Year (April - March)
    today = datetime.now()
    fy_start = today.year if today.month >= 4 else today.year - 1
    fy_str = f"{fy_start}-{(fy_start + 1) % 100:02d}"

    return render_template(
        "dashboard.html",
        total_projects=total_projects,
        total_project_value=total_project_value,
        total_sales=total_sales,
        total_labour=total_labour,
        total_income=total_income,
        total_expense=total_expense,
        low_stock_count=low_stock_count,
        pending_approvals=pending_approvals,
        pending_gm_approvals=pending_gm_approvals,
        recent_bills=recent_bills,
        status_labels=status_labels,
        status_counts=status_counts,
        today=today,
        fy_str=fy_str,
    )


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not session.get("username"):
        return redirect(url_for("login"))

    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash("New passwords do not match!", "error")
            return redirect(url_for("change_password"))

        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return redirect(url_for("change_password"))

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session["username"],)).fetchone()

        if user and verify_password(old_password, user["salt"], user["password_hash"]):
            new_salt, new_hash = hash_password(new_password)
            conn.execute("UPDATE users SET salt = ?, password_hash = ? WHERE id = ?", (new_salt, new_hash, user["id"]))
            conn.commit()
            conn.close()
            flash("Password changed successfully! Please login again.", "success")
            session.clear()
            return redirect(url_for("login"))
        else:
            flash("Incorrect Old Password.", "error")

        conn.close()
        return redirect(url_for("change_password"))

    return render_template("change_password.html")


# ------------------------------------------------------------------
# USER MANAGEMENT
# ------------------------------------------------------------------
@app.route("/users", methods=["GET", "POST"])
def users():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "Admin")

        if not username or not password:
            flash("Username and Password are required.", "error")
        else:
            salt, password_hash = hash_password(password)
            try:
                conn.execute("INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)", (username, salt, password_hash, role))
                conn.commit()
                flash(f"User '{username}' created successfully!", "success")
            except sqlite3.IntegrityError:
                flash("Username already exists!", "error")
        conn.close()
        return redirect(url_for("users"))

    user_list = conn.execute("SELECT id, username, role FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("users.html", users=user_list)


@app.route("/users/delete/<int:id>")
def delete_user(id):
    if not session.get("username"):
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Only Admin can delete users.", "error")
        return redirect(url_for("users"))

    conn = get_db()
    target = conn.execute("SELECT username FROM users WHERE id = ?", (id,)).fetchone()
    if not target:
        flash("User not found!", "error")
    elif target["username"] == session.get("username"):
        flash("You cannot delete your own account.", "error")
    else:
        conn.execute("DELETE FROM users WHERE id = ?", (id,))
        conn.commit()
        flash("User deleted successfully!", "success")
    conn.close()
    return redirect(url_for("users"))


@app.route("/users/edit/<int:id>", methods=["POST"])
def edit_user_role(id):
    if not session.get("username"):
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        flash("Only Admin can edit user roles.", "error")
        return redirect(url_for("users"))

    new_role = request.form.get("role")
    conn = get_db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, id))
    conn.commit()
    conn.close()
    flash("User role updated successfully!", "success")
    return redirect(url_for("users"))


# ------------------------------------------------------------------
# SEARCH
# ------------------------------------------------------------------
@app.route("/search")
def search():
    if not session.get("username"):
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip()
    if not query:
        return redirect(url_for("dashboard"))

    conn = get_db()
    search_term = f"%{query}%"

    projects = conn.execute("SELECT * FROM projects WHERE project_name LIKE ? OR client_name LIKE ?", (search_term, search_term)).fetchall()

    purchases = conn.execute("""
        SELECT DISTINCT p.* FROM purchases p
        LEFT JOIN purchase_items pi ON p.id = pi.purchase_id
        WHERE p.invoice_number LIKE ? OR p.supplier_name LIKE ? OR pi.material_name LIKE ? OR pi.description LIKE ?
    """, (search_term, search_term, search_term, search_term)).fetchall()

    pos = conn.execute("SELECT * FROM po WHERE vendor_name LIKE ? OR quotation_no LIKE ? OR project_name LIKE ?", (search_term, search_term, search_term)).fetchall()
    parties = conn.execute("SELECT * FROM parties WHERE party_name LIKE ? OR gstin LIKE ?", (search_term, search_term)).fetchall()

    bills = conn.execute("""
        SELECT DISTINCT b.* FROM bills b
        LEFT JOIN bill_items bi ON b.id = bi.bill_id
        WHERE b.bill_no LIKE ? OR b.project_name LIKE ? OR bi.description LIKE ?
    """, (search_term, search_term, search_term)).fetchall()

    accounts = conn.execute("SELECT * FROM accounts WHERE description LIKE ? OR paid_name LIKE ?", (search_term, search_term)).fetchall()
    labours = conn.execute("SELECT * FROM labour WHERE labour_name LIKE ? OR designation LIKE ?", (search_term, search_term)).fetchall()

    conn.close()

    return render_template("search_results.html", query=query, projects=projects, purchases=purchases, pos=pos, parties=parties, bills=bills, accounts=accounts, labours=labours)


# ----------------------------------
# TENDER & ESTIMATION
# ----------------------------------
@app.route("/tenders", methods=["GET", "POST"])
def tenders():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        tender_no = request.form.get("tender_no", "").strip()
        client_name = request.form.get("client_name", "").strip()
        tender_date = request.form.get("tender_date")
        submission_date = request.form.get("submission_date")

        if tender_no and client_name:
            conn.execute("INSERT INTO tenders (tender_no, client_name, tender_date, submission_date) VALUES (?, ?, ?, ?)",
                         (tender_no, client_name, tender_date, submission_date))
            conn.commit()
            flash("Tender created successfully!", "success")
            conn.close()
            return redirect(url_for("tenders"))

    tender_list = conn.execute("SELECT * FROM tenders ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("tenders.html", tenders=tender_list)


@app.route("/tender/<int:id>", methods=["GET", "POST"])
def tender_items(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        descriptions = request.form.getlist("description[]")
        units = request.form.getlist("unit[]")
        quantities = request.form.getlist("quantity[]")
        rates = request.form.getlist("rate[]")

        for i in range(len(descriptions)):
            if descriptions[i].strip():
                qty = float(quantities[i]) if quantities[i] else 0
                rate = float(rates[i]) if rates[i] else 0
                amt = round(qty * rate, 2)
                conn.execute("INSERT INTO tender_items (tender_id, description, unit, quantity, rate, amount) VALUES (?, ?, ?, ?, ?, ?)",
                             (id, descriptions[i], units[i], qty, rate, amt))

        total = conn.execute("SELECT SUM(amount) FROM tender_items WHERE tender_id = ?", (id,)).fetchone()[0] or 0
        conn.execute("UPDATE tenders SET estimated_value = ? WHERE id = ?", (total, id))
        conn.commit()
        flash("Estimation items added!", "success")
        conn.close()
        return redirect(url_for("tender_items", id=id))

    tender = conn.execute("SELECT * FROM tenders WHERE id = ?", (id,)).fetchone()
    items = conn.execute("SELECT * FROM tender_items WHERE tender_id = ?", (id,)).fetchall()
    conn.close()
    return render_template("tender_items.html", tender=tender, items=items)


@app.route("/tender/update_status/<int:id>/<status>")
def update_tender_status(id, status):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE tenders SET status = ? WHERE id = ?", (status, id))
    conn.commit()
    conn.close()
    flash(f"Tender marked as {status}!", "success")
    return redirect(url_for("tenders"))


@app.route("/tender/convert/<int:id>")
def convert_tender(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    tender = conn.execute("SELECT * FROM tenders WHERE id = ?", (id,)).fetchone()
    if tender and tender['status'] == 'Won':
        
        # FIX: Check if the client exists in Party Master as a Debtor
        client_exists = conn.execute("SELECT id FROM parties WHERE party_name = ? AND party_type = 'Debtor'", (tender['client_name'],)).fetchone()
        
        if not client_exists:
            flash(f"Client '{tender['client_name']}' not found in Party Master. Please create the party first.", "error")
            conn.close()
            # Redirect to parties page and pre-fill the name
            return redirect(url_for("parties", new_name=tender['client_name']))

        existing = conn.execute("SELECT id FROM projects WHERE project_name = ?", (tender['tender_no'],)).fetchone()
        if not existing:
            conn.execute("INSERT INTO projects (project_name, client_name, project_value, status) VALUES (?, ?, ?, 'In Progress')",
                         (tender['tender_no'], tender['client_name'], tender['estimated_value']))

            items = conn.execute("SELECT * FROM tender_items WHERE tender_id = ?", (id,)).fetchall()
            for item in items:
                conn.execute("INSERT INTO poq (project_name, material_name, unit, quantity, rate, amount, supply_rate, erection_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (tender['tender_no'], item['description'], item['unit'], item['quantity'], item['rate'], item['amount'], item['rate'], 0))

            conn.commit()
            flash("Tender successfully converted to Project & BOQ!", "success")
        else:
            flash("Project already exists for this Tender!", "error")

    conn.close()
    return redirect(url_for("tenders"))


# ------------------------------------------------------------------
# PROJECTS
# ------------------------------------------------------------------
@app.route("/projects", methods=["GET", "POST"])
def projects():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    if request.method == "POST":
        project_name = request.form.get("project_name", "").strip()
        client_name = request.form.get("client_name", "").strip()
        work_order = request.form.get("work_order", "").strip()
        start_date = request.form.get("start_date", "")
        status = request.form.get("status", "Planning")

        try:
            project_value = float(request.form.get("project_value") or 0)
            if not project_name or not client_name:
                flash("Project Name and Client Name are required.", "error")
            else:
                conn.execute("INSERT INTO projects (project_name, client_name, work_order, project_value, start_date, status) VALUES (?, ?, ?, ?, ?, ?)", (project_name, client_name, work_order, project_value, start_date, status))
                conn.commit()
                flash("Project saved successfully!", "success")
                conn.close()
                return redirect(url_for("projects"))
        except ValueError:
            flash("Please enter a valid Project Value.", "error")

    project_list = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    debtors = conn.execute("SELECT party_name FROM parties WHERE party_type = 'Debtor' ORDER BY party_name").fetchall()
    conn.close()
    return render_template("projects.html", projects=project_list, debtors=debtors)


@app.route("/projects/delete/<int:id>")
def delete_project(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("DELETE FROM projects WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Project deleted successfully!", "success")
    return redirect(url_for("projects"))


@app.route("/projects/edit/<int:id>", methods=["GET", "POST"])
def edit_project(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        project_name = request.form.get("project_name", "").strip()
        client_name = request.form.get("client_name", "").strip()
        work_order = request.form.get("work_order", "").strip()
        start_date = request.form.get("start_date", "")
        status = request.form.get("status", "Planning")
        try:
            project_value = float(request.form.get("project_value") or 0)
            conn.execute("UPDATE projects SET project_name=?, client_name=?, work_order=?, project_value=?, start_date=?, status=? WHERE id=?", (project_name, client_name, work_order, project_value, start_date, status, id))
            conn.commit()
            flash("Project updated successfully!", "success")
            conn.close()
            return redirect(url_for("projects"))
        except ValueError:
            flash("Invalid Project Value.", "error")
    project = conn.execute("SELECT * FROM projects WHERE id = ?", (id,)).fetchone()
    debtors = conn.execute("SELECT party_name FROM parties WHERE party_type = 'Debtor' ORDER BY party_name").fetchall()
    conn.close()
    return render_template("edit_project.html", project=project, debtors=debtors)


# ------------------------------------------------------------------
# PURCHASES
# ------------------------------------------------------------------
@app.route("/purchases", methods=["GET", "POST"])
def purchases():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = None
    try:
        conn = get_db()
        if request.method == "POST":
            po_number = request.form.get("po_number", "").strip()
            project_name = request.form.get("project_name", "").strip()
            supplier_name = request.form.get("supplier_name", "").strip()
            invoice_number = request.form.get("invoice_number", "").strip()
            invoice_date = request.form.get("invoice_date", "")

            cursor = conn.cursor()
            material_names = request.form.getlist("material_name[]")
            descriptions = request.form.getlist("description[]")
            quantities = request.form.getlist("quantity[]")
            rates = request.form.getlist("rate[]")
            gst_rates = request.form.getlist("gst_rate[]")

            grand_total = 0
            total_gst = 0
            sub_total = 0
            items_to_insert = []

            for i in range(len(material_names)):
                if material_names[i].strip():
                    qty = float(quantities[i]) if quantities[i] else 0
                    rate = float(rates[i]) if rates[i] else 0
                    gst = float(gst_rates[i]) if gst_rates[i] else 0

                    basic_amt = round(qty * rate, 2)
                    gst_amt = round(basic_amt * (gst / 100), 2)
                    total_amt = round(basic_amt + gst_amt, 2)

                    sub_total += basic_amt
                    total_gst += gst_amt
                    grand_total += total_amt

                    items_to_insert.append({
                        "material": material_names[i],
                        "desc": descriptions[i] if i < len(descriptions) else "",
                        "qty": qty,
                        "rate": rate,
                        "gst": gst,
                        "total_amt": total_amt
                    })

            if not po_number:
                flash("Please select a PO Number.", "error")
            elif not project_name or not supplier_name or not invoice_number:
                flash("Project, Supplier, and Invoice Number are required.", "error")
            elif not items_to_insert:
                flash("Please add at least one item.", "error")
            else:
                cursor.execute("""
                    INSERT INTO purchases (po_number, project_name, supplier_name, invoice_number, invoice_date, subtotal, gst_amount, total_amount)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (po_number, project_name, supplier_name, invoice_number, invoice_date, round(sub_total, 2), round(total_gst, 2), round(grand_total, 2)))
                purchase_id = cursor.lastrowid

                for item in items_to_insert:
                    cursor.execute("""
                        INSERT INTO purchase_items (purchase_id, material_name, description, quantity, rate, gst_rate, amount)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (purchase_id, item["material"], item["desc"], item["qty"], item["rate"], item["gst"], item["total_amt"]))

                    cursor.execute("""
                        INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (item["material"], invoice_date, 'Receipt', invoice_number, project_name, item["qty"], item["rate"]))

                conn.commit()
                flash("Purchase saved and Inventory updated successfully!", "success")
                conn.close()
                return redirect(url_for("purchases"))

        purchase_list = conn.execute("SELECT * FROM purchases ORDER BY id DESC").fetchall()

        materials_raw = conn.execute("SELECT material_name, unit FROM stock ORDER BY material_name").fetchall()
        materials = [dict(row) for row in materials_raw]

        po_items_raw = conn.execute("""
            SELECT po.id as po_id, po.project_name, po.vendor_name,
                   po_items.material_name, po_items.quantity, po_items.rate, po_items.unit
            FROM po
            JOIN po_items ON po.id = po_items.po_id
            WHERE po.gm_approval = 'Approved'
            ORDER BY po.id DESC
        """).fetchall()
        po_items_list = [dict(row) for row in po_items_raw]

        conn.close()
        return render_template("purchases.html", purchases=purchase_list, materials=materials, po_items_list=po_items_list)

    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        print(f"Purchases route error: {e}")
        flash("A database error occurred while processing the purchase.", "error")
        return redirect(url_for("purchases"))


@app.route("/purchases/delete/<int:id>")
def delete_purchase(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("DELETE FROM purchase_items WHERE purchase_id = ?", (id,))
    conn.execute("DELETE FROM purchases WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Purchase record deleted successfully!", "success")
    return redirect(url_for("purchases"))


@app.route("/purchases/edit/<int:id>", methods=["GET", "POST"])
def edit_purchase(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        project_name = request.form.get("project_name", "").strip()
        supplier_name = request.form.get("supplier_name", "").strip()
        invoice_number = request.form.get("invoice_number", "").strip()
        invoice_date = request.form.get("invoice_date", "")
        material_description = request.form.get("material_description", "").strip()
        try:
            quantity = float(request.form.get("quantity") or 0)
            rate = float(request.form.get("rate") or 0)
            gst_rate = float(request.form.get("gst_rate") or 0)
            subtotal = round(quantity * rate, 2)
            gst_amount = round(subtotal * (gst_rate / 100), 2)
            total_amount = round(subtotal + gst_amount, 2)

            conn.execute("UPDATE purchases SET project_name=?, supplier_name=?, invoice_number=?, invoice_date=?, material_description=?, quantity=?, rate=?, gst_rate=?, subtotal=?, gst_amount=?, total_amount=? WHERE id=?", (project_name, supplier_name, invoice_number, invoice_date, material_description, quantity, rate, gst_rate, subtotal, gst_amount, total_amount, id))
            conn.commit()
            flash("Purchase updated successfully!", "success")
            conn.close()
            return redirect(url_for("purchases"))
        except ValueError:
            flash("Invalid numeric values.", "error")
    purchase = conn.execute("SELECT * FROM purchases WHERE id = ?", (id,)).fetchone()
    conn.close()
    return render_template("edit_purchase.html", purchase=purchase)


# ------------------------------------------------------------------
# STOCK
# ------------------------------------------------------------------
@app.route("/stock", methods=["GET", "POST"])
def stock():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    if request.method == "POST":
        form_type = request.form.get("form_type")
        if form_type == "material":
            material_code = request.form.get("material_code", "").strip()
            material_name = request.form.get("material_name", "").strip()
            unit = request.form.get("unit", "Nos")
            try:
                opening_stock = float(request.form.get("opening_stock") or 0)
                reorder_level = float(request.form.get("reorder_level") or 0)
                if material_name:
                    conn.execute("INSERT INTO stock (material_code, material_name, unit, opening_stock, reorder_level) VALUES (?, ?, ?, ?, ?)", (material_code, material_name, unit, opening_stock, reorder_level))
                    conn.commit()
                    flash("Material added successfully!", "success")
            except ValueError:
                flash("Invalid numbers entered.", "error")
        elif form_type == "ledger":
            material_name = request.form.get("material_name")
            transaction_date = request.form.get("transaction_date")
            transaction_type = request.form.get("transaction_type")
            invoice_no = request.form.get("invoice_no", "")
            project_name = request.form.get("project_name", "")
            try:
                quantity = float(request.form.get("quantity") or 0)
                rate = float(request.form.get("rate") or 0)
                conn.execute("INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate) VALUES (?, ?, ?, ?, ?, ?, ?)", (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate))
                conn.commit()
                flash("Inventory Entry recorded!", "success")
            except ValueError:
                flash("Invalid quantity or rate.", "error")
        conn.close()
        return redirect(url_for("stock"))

    materials = conn.execute("SELECT * FROM stock").fetchall()
    summary_list = []
    for m in materials:
        receipts = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name = ? AND transaction_type = 'Receipt'", (m['material_name'],)).fetchone()[0] or 0
        issues = conn.execute("SELECT SUM(quantity) FROM stock_ledger WHERE material_name = ? AND transaction_type = 'Issue'", (m['material_name'],)).fetchone()[0] or 0
        available = m['opening_stock'] + receipts - issues
        last_rate = conn.execute("SELECT rate FROM stock_ledger WHERE material_name = ? AND transaction_type = 'Receipt' ORDER BY id DESC LIMIT 1", (m['material_name'],)).fetchone()
        current_rate = last_rate[0] if last_rate else 0
        total_value = available * current_rate

        summary_list.append({
            "id": m['id'],
            "material_code": m['material_code'],
            "material_name": m['material_name'],
            "unit": m['unit'],
            "opening_stock": m['opening_stock'],
            "total_receipts": receipts,
            "total_issues": issues,
            "available_stock": available,
            "current_rate": current_rate,
            "total_value": total_value,
            "reorder_level": m['reorder_level']
        })

    raw_ledger = conn.execute("SELECT * FROM stock_ledger ORDER BY transaction_date ASC, id ASC").fetchall()
    ledger_list = []
    running_balances = {}
    for row in raw_ledger:
        m_name = row['material_name']
        if m_name not in running_balances:
            m_data = conn.execute("SELECT opening_stock FROM stock WHERE material_name = ?", (m_name,)).fetchone()
            running_balances[m_name] = m_data['opening_stock'] if m_data else 0
        if row['transaction_type'] == 'Receipt':
            running_balances[m_name] += row['quantity']
        else:
            running_balances[m_name] -= row['quantity']
        ledger_list.append({"date": row['transaction_date'], "material": m_name, "type": row['transaction_type'], "invoice": row['invoice_no'], "project": row['project_name'], "in_qty": row['quantity'] if row['transaction_type'] == 'Receipt' else 0, "out_qty": row['quantity'] if row['transaction_type'] == 'Issue' else 0, "rate": row['rate'], "balance": running_balances[m_name]})

    low_stock_list = [item for item in summary_list if item['available_stock'] <= item['reorder_level']]
    project_material_report = conn.execute("SELECT project_name, material_name, SUM(quantity) as total_issued FROM stock_ledger WHERE transaction_type = 'Issue' AND project_name != '' AND project_name IS NOT NULL GROUP BY project_name, material_name ORDER BY project_name").fetchall()
    project_list = conn.execute("SELECT project_name FROM projects").fetchall()
    conn.close()

    return render_template("stock.html", summary_list=summary_list, ledger_list=ledger_list, low_stock_list=low_stock_list, project_material_report=project_material_report, project_list=project_list)


@app.route("/stock/delete/<int:id>")
def delete_stock(id):
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    material = conn.execute("SELECT material_name FROM stock WHERE id = ?", (id,)).fetchone()

    if not material:
        flash("Material not found!", "error")
        conn.close()
        return redirect(url_for("stock"))

    m_name = material['material_name']
    ledger_count = conn.execute("SELECT COUNT(*) FROM stock_ledger WHERE material_name = ?", (m_name,)).fetchone()[0]

    force = request.args.get("force") == "1"
    if ledger_count and not force:
        flash(f"Cannot delete '{m_name}': {ledger_count} ledger entries exist. Add ?force=1 to the URL to force delete.", "error")
    else:
        conn.execute("DELETE FROM stock WHERE id = ?", (id,))
        conn.execute("DELETE FROM stock_ledger WHERE material_name = ?", (m_name,))
        conn.commit()
        flash(f"Material '{m_name}' and its ledger history deleted successfully!", "success")

    conn.close()
    return redirect(url_for("stock"))


# ------------------------------------------------------------------
# MATERIAL ISSUE
# ------------------------------------------------------------------
@app.route("/material_issue", methods=["GET", "POST"])
def material_issue():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        project_name = request.form.get("project_name")
        issue_date = request.form.get("issue_date")
        issued_to = request.form.get("issued_to", "")

        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO material_issues (project_name, issue_date, issued_to) VALUES (?, ?, ?)", (project_name, issue_date, issued_to))
            issue_id = cursor.lastrowid

            material_names = request.form.getlist("material_name[]")
            quantities = request.form.getlist("quantity[]")
            rates = request.form.getlist("rate[]")

            total_expense = 0

            for i in range(len(material_names)):
                if material_names[i].strip():
                    qty = float(quantities[i]) if quantities[i] else 0
                    rt = float(rates[i]) if rates[i] else 0
                    amt = round(qty * rt, 2)
                    total_expense += amt

                    cursor.execute("INSERT INTO material_issue_items (issue_id, material_name, quantity, rate, amount) VALUES (?, ?, ?, ?, ?)", (issue_id, material_names[i], qty, rt, amt))

                    cursor.execute("""
                        INSERT INTO stock_ledger (material_name, transaction_date, transaction_type, invoice_no, project_name, quantity, rate)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (material_names[i], issue_date, 'Issue', f"MIN-{issue_id}", project_name, qty, rt))

            if total_expense > 0:
                cursor.execute("""
                    INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (issue_date, f"Material Issued (MIN-{issue_id})", total_expense, 'Expense', project_name, 'Store', 'M'))

            conn.commit()
            flash("Material Issued successfully! Inventory & Accounts updated.", "success")
        except Exception as e:
            flash(f"Error: {str(e)}", "error")

        conn.close()
        return redirect(url_for("material_issue"))

    issue_list = conn.execute("SELECT * FROM material_issues ORDER BY id DESC").fetchall()
    project_list = conn.execute("SELECT project_name FROM projects").fetchall()
    materials = conn.execute("SELECT material_name, unit FROM stock").fetchall()

    conn.close()
    return render_template("material_issue.html", issue_list=issue_list, project_list=project_list, materials=materials)


@app.route("/material_issue/print/<int:id>")
def print_material_issue(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    issue = conn.execute("SELECT * FROM material_issues WHERE id = ?", (id,)).fetchone()
    items = conn.execute("SELECT * FROM material_issue_items WHERE issue_id = ?", (id,)).fetchall()
    project = conn.execute("SELECT * FROM projects WHERE project_name = ?", (issue['project_name'],)).fetchone() if issue else None
    conn.close()

    if not issue:
        flash("Issue record not found!", "error")
        return redirect(url_for("material_issue"))

    return render_template("print_material_issue.html", issue=issue, items=items, project=project)


# ------------------------------------------------------------------
# LABOUR & ATTENDANCE
# ------------------------------------------------------------------
@app.route("/labour", methods=["GET", "POST"])
def labour():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    if request.method == "POST":
        labour_name = request.form.get("labour_name", "").strip()
        designation = request.form.get("designation", "").strip()
        contact_number = request.form.get("contact_number", "").strip()
        join_date = request.form.get("join_date", "")
        project_name = request.form.get("project_name", "").strip()
        try:
            daily_wage = float(request.form.get("daily_wage") or 0)
            if not labour_name:
                flash("Labour Name is required.", "error")
            else:
                conn.execute("INSERT INTO labour (labour_name, designation, daily_wage, contact_number, join_date, project_name) VALUES (?, ?, ?, ?, ?, ?)", (labour_name, designation, daily_wage, contact_number, join_date, project_name))
                conn.commit()
                flash("Labour added successfully!", "success")
                conn.close()
                return redirect(url_for("labour"))
        except ValueError:
            flash("Please enter a valid Wage amount.", "error")

    labour_list = conn.execute("SELECT * FROM labour ORDER BY id DESC").fetchall()
    project_list = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
    conn.close()
    return render_template("labour.html", labour_list=labour_list, project_list=project_list)


@app.route("/attendance", methods=["GET", "POST"])
def attendance():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    selected_date = request.args.get("date") or datetime.now().strftime("%Y-%m-%d")

    if request.method == "POST":
        date = request.form.get("attendance_date")
        conn.execute("DELETE FROM labour_attendance WHERE attendance_date = ?", (date,))
        for key, value in request.form.items():
            if key.startswith("status_"):
                labour_id = key.split("_")[1]
                project_name = request.form.get(f"project_{labour_id}", "")
                conn.execute("INSERT INTO labour_attendance (labour_id, attendance_date, status, project_name) VALUES (?, ?, ?, ?)", (labour_id, date, value, project_name))
        conn.commit()
        flash("Attendance saved successfully!", "success")
        conn.close()
        return redirect(url_for("attendance", date=date))

    labours = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    existing_attendance = conn.execute("SELECT * FROM labour_attendance WHERE attendance_date = ?", (selected_date,)).fetchall()
    att_dict = {str(a['labour_id']): a for a in existing_attendance}
    conn.close()
    return render_template("attendance.html", labours=labours, selected_date=selected_date, att_dict=att_dict)


@app.route("/attendance_report")
def attendance_report():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    selected_month = request.args.get("month") or datetime.now().strftime("%Y-%m")
    labours = conn.execute("SELECT * FROM labour ORDER BY labour_name").fetchall()
    report_data = []
    for l in labours:
        present_days = conn.execute("SELECT COUNT(*) FROM labour_attendance WHERE labour_id = ? AND status = 'Present' AND strftime('%Y-%m', attendance_date) = ?", (l['id'], selected_month)).fetchone()[0]
        total_salary = present_days * l['daily_wage']
        report_data.append({"id": l['id'], "name": l['labour_name'], "designation": l['designation'], "wage": l['daily_wage'], "present_days": present_days, "total_salary": total_salary, "project": l['project_name']})
    conn.close()
    return render_template("attendance_report.html", report_data=report_data, selected_month=selected_month)


# ------------------------------------------------------------------
# ACCOUNTS / BILLS ENTRY
# ------------------------------------------------------------------
@app.route("/accounts_entry", methods=["GET", "POST"])
def accounts_entry():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    selected_project = request.args.get("project", "") or request.form.get("project_name", "")

    edit_bill_id = request.args.get("edit_bill")
    edit_account_id = request.args.get("edit_account")

    if request.method == "POST":
        form_type = request.form.get("form_type")

        if form_type == "bill":
            bill_no = request.form.get("bill_no", "").strip()
            bill_date = request.form.get("bill_date", "")
            bill_type = request.form.get("bill_type", "BOQ")
            edit_id = request.form.get("edit_id")

            try:
                cursor = conn.cursor()
                descriptions   = request.form.getlist("description[]")
                hsn_codes      = request.form.getlist("hsn_sac[]")
                quantities     = request.form.getlist("quantity[]")
                supply_rates   = request.form.getlist("supply_rate[]")
                erection_rates = request.form.getlist("erection_rate[]")
                gst_rates      = request.form.getlist("gst_rate[]")

                grand_total = 0
                items_to_insert = []

                for i in range(len(descriptions)):
                    if descriptions[i].strip():
                        qty = float(quantities[i])     if quantities[i]     else 0
                        sup = float(supply_rates[i])   if supply_rates[i]   else 0
                        ere = float(erection_rates[i]) if erection_rates[i] else 0
                        gst = float(gst_rates[i])      if gst_rates[i]      else 0

                        total_rate = sup + ere
                        basic_amt  = round(qty * total_rate, 2)
                        gst_amt    = round(basic_amt * (gst / 100), 2)
                        total_amt  = round(basic_amt + gst_amt, 2)

                        grand_total += total_amt

                        items_to_insert.append({
                            "description":   descriptions[i],
                            "hsn_sac":       hsn_codes[i] if i < len(hsn_codes) else "",
                            "quantity":      qty,
                            "supply_rate":   sup,
                            "erection_rate": ere,
                            "rate":          total_rate,
                            "gst_rate":      gst,
                            "basic_amount":  basic_amt,
                            "gst_amount":    gst_amt,
                            "total_amount":  total_amt
                        })

                exact_total = grand_total
                grand_total = round(exact_total)

                if bill_no and selected_project and items_to_insert:
                    if edit_id:
                        cursor.execute(
                            "UPDATE bills SET bill_no=?, bill_date=?, total_value=?, bill_type=? WHERE id=?",
                            (bill_no, bill_date, grand_total, bill_type, edit_id)
                        )
                        cursor.execute("DELETE FROM bill_items WHERE bill_id = ?", (edit_id,))
                        bill_id = edit_id
                        flash("Bill updated successfully!", "success")
                    else:
                        cursor.execute(
                            "INSERT INTO bills (project_name, bill_no, bill_date, total_value, bill_type) VALUES (?, ?, ?, ?, ?)",
                            (selected_project, bill_no, bill_date, grand_total, bill_type)
                        )
                        bill_id = cursor.lastrowid
                        flash("Bill added successfully!", "success")

                    for item in items_to_insert:
                        cursor.execute("""
                            INSERT INTO bill_items
                            (bill_id, description, hsn_sac, quantity, rate, supply_rate, erection_rate, gst_rate, basic_amount, gst_amount, total_amount)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (bill_id, item["description"], item["hsn_sac"], item["quantity"],
                              item["rate"], item["supply_rate"], item["erection_rate"],
                              item["gst_rate"], item["basic_amount"], item["gst_amount"], item["total_amount"]))

                    conn.commit()
                else:
                    flash("Bill No, Project and at least one item required.", "error")

            except Exception as e:
                flash(f"Error: {str(e)}", "error")

            conn.close()
            return redirect(url_for("accounts_entry", project=selected_project, tab='tab1'))

        elif form_type == "ledger":
            transaction_date = request.form.get("transaction_date", "")
            description = request.form.get("description", "").strip()
            transaction_type = request.form.get("transaction_type", "Income")
            paid_name = request.form.get("paid_name", "").strip()
            category = request.form.get("category", "")
            edit_id = request.form.get("edit_id")

            try:
                amount = float(request.form.get("amount") or 0)
                if not description:
                    flash("Particulars is required.", "error")
                else:
                    if edit_id:
                        conn.execute("""
                            UPDATE accounts SET transaction_date=?, description=?, amount=?, transaction_type=?, paid_name=?, category=?
                            WHERE id=?
                        """, (transaction_date, description, amount, transaction_type, paid_name, category, edit_id))
                        flash("Entry updated successfully!", "success")
                    else:
                        conn.execute("INSERT INTO accounts (transaction_date, description, amount, transaction_type, project_name, paid_name, category) VALUES (?, ?, ?, ?, ?, ?, ?)", (transaction_date, description, amount, transaction_type, selected_project, paid_name, category))
                        flash("Entry recorded successfully!", "success")

                    conn.commit()
                    conn.close()
                    return redirect(url_for("accounts_entry", project=selected_project, tab='tab2'))
            except ValueError:
                flash("Please enter a valid amount.", "error")

    # GET Request
    edit_bill_data = None
    edit_bill_items = []
    edit_account_data = None

    if edit_bill_id:
        b_row = conn.execute("SELECT * FROM bills WHERE id = ?", (edit_bill_id,)).fetchone()
        if b_row:
            edit_bill_data = dict(b_row)
            i_rows = conn.execute("SELECT * FROM bill_items WHERE bill_id = ?", (edit_bill_id,)).fetchall()
            edit_bill_items = [dict(r) for r in i_rows]

    if edit_account_id:
        a_row = conn.execute("SELECT * FROM accounts WHERE id = ?", (edit_account_id,)).fetchone()
        if a_row:
            edit_account_data = dict(a_row)

    active_tab = request.args.get("tab", "tab1")
    if edit_account_id:
        active_tab = "tab2"

    project_list = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    parties_list = conn.execute("SELECT party_name FROM parties ORDER BY party_name").fetchall()

    project_details = None
    bills_list = []
    accounts_list = []
    total_income = 0
    total_expense = 0
    cumulative_bills = 0
    project_boq_items = []

    if selected_project:
        project_details = conn.execute("SELECT * FROM projects WHERE project_name = ?", (selected_project,)).fetchone()
        if project_details:
            bills_list = conn.execute("SELECT * FROM bills WHERE project_name = ? ORDER BY id DESC", (selected_project,)).fetchall()
            cumulative_bills = sum((b['total_value'] or 0) for b in bills_list)

            accounts_list = conn.execute("SELECT * FROM accounts WHERE project_name = ? ORDER BY transaction_date DESC, id DESC", (selected_project,)).fetchall()
            total_income = sum((row['amount'] or 0) for row in accounts_list if row['transaction_type'] == 'Income')
            total_expense = sum((row['amount'] or 0) for row in accounts_list if row['transaction_type'] == 'Expense')

            project_boq_items = conn.execute("SELECT * FROM poq WHERE project_name = ?", (selected_project,)).fetchall()

    conn.close()
    return render_template("entry.html",
                           project_list=project_list, selected_project=selected_project,
                           project_details=project_details, bills=bills_list,
                           accounts=accounts_list, total_income=total_income,
                           total_expense=total_expense, cumulative_bills=cumulative_bills,
                           parties_list=parties_list, project_boq_items=project_boq_items,
                           edit_bill_data=edit_bill_data, edit_bill_items=edit_bill_items,
                           edit_account_data=edit_account_data, active_tab=active_tab)


@app.route("/accounts/delete/<int:id>")
def delete_account_entry(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    project_name = request.args.get("project", "")
    tab = request.args.get("tab", "tab4")
    conn = get_db()
    conn.execute("DELETE FROM accounts WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Ledger entry deleted successfully!", "success")
    return redirect(url_for("accounts_entry", project=project_name, tab=tab))


@app.route("/bills/delete/<int:id>")
def delete_bill(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    project_name = request.args.get("project", "")
    tab = request.args.get("tab", "tab3")
    conn = get_db()
    conn.execute("DELETE FROM bill_items WHERE bill_id = ?", (id,))
    conn.execute("DELETE FROM bills WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Bill entry deleted successfully!", "success")
    return redirect(url_for("accounts_entry", project=project_name, tab=tab))


@app.route("/bill/print/<int:id>")
def print_bill(id):
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    bill = conn.execute("SELECT * FROM bills WHERE id = ?", (id,)).fetchone()
    if not bill:
        flash("Bill not found!", "error")
        conn.close()
        return redirect(url_for("accounts"))

    items = conn.execute("SELECT * FROM bill_items WHERE bill_id = ?", (id,)).fetchall()
    project = conn.execute("SELECT * FROM projects WHERE project_name = ?", (bill['project_name'],)).fetchone()
    client = conn.execute("SELECT * FROM parties WHERE party_name = ? AND party_type = 'Debtor'", (project['client_name'],)).fetchone() if project else None
    conn.close()

    exact_total = sum((i['total_amount'] or 0) for i in items)
    rounded_total = round(exact_total)
    round_off = rounded_total - exact_total

    amount_in_words = num_to_words(rounded_total)

    return render_template("print_bill.html", bill=bill, items=items, project=project, client=client, amount_in_words=amount_in_words, rounded_total=rounded_total, round_off=round_off)


# ------------------------------------------------------------------
# ACCOUNTS / P&L
# ------------------------------------------------------------------
@app.route("/accounts", methods=["GET"])
def accounts():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    all_projects = conn.execute("SELECT * FROM projects").fetchall()
    project_list = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()

    pnl_list = []
    for p in all_projects:
        p_name = p['project_name']
        p_income = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name = ? AND transaction_type = 'Income'", (p_name,)).fetchone()[0] or 0
        p_expense = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name = ? AND transaction_type = 'Expense'", (p_name,)).fetchone()[0] or 0
        p_profit = p_income - p_expense
        pnl_list.append({
            "id": p['id'], "project_name": p_name, "client": p['client_name'], "value": p['project_value'],
            "income": p_income, "expense": p_expense, "profit": p_profit
        })

    conn.close()
    return render_template("accounts.html", pnl_list=pnl_list, project_list=project_list)


@app.route("/project_pnl/<project_name>")
def project_pnl_detail(project_name):
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    project = conn.execute("SELECT * FROM projects WHERE project_name = ?", (project_name,)).fetchone()
    transactions = conn.execute("""
        SELECT * FROM accounts
        WHERE project_name = ?
        ORDER BY transaction_date ASC, id ASC
    """, (project_name,)).fetchall()
    conn.close()

    total_inflow = sum(t['amount'] for t in transactions if t['transaction_type'] == 'Income')
    total_outflow = sum(t['amount'] for t in transactions if t['transaction_type'] == 'Expense')
    net_profit = total_inflow - total_outflow

    return render_template("project_pnl_detail.html",
                           project=project,
                           transactions=transactions,
                           total_inflow=total_inflow,
                           total_outflow=total_outflow,
                           net_profit=net_profit)


# ------------------------------------------------------------------
# PARTIES
# ------------------------------------------------------------------
@app.route("/parties", methods=["GET", "POST"])
def parties():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        party_name = request.form.get("party_name", "").strip()
        party_type = request.form.get("party_type", "Debtor")
        contact_number = request.form.get("contact_number", "").strip()
        email = request.form.get("email", "").strip()
        gstin = request.form.get("gstin", "").strip()
        address = request.form.get("address", "").strip()
        try:
            opening_balance = float(request.form.get("opening_balance") or 0)
            if not party_name or not gstin:
                flash("Party Name and GSTIN are required.", "error")
            else:
                existing = conn.execute("SELECT id FROM parties WHERE party_name = ? OR gstin = ?", (party_name, gstin)).fetchone()

                if existing:
                    flash(f"Error: Party Name '{party_name}' or GSTIN '{gstin}' already exists!", "error")
                else:
                    conn.execute("INSERT INTO parties (party_name, party_type, contact_number, email, gstin, address, opening_balance) VALUES (?, ?, ?, ?, ?, ?, ?)", (party_name, party_type, contact_number, email, gstin, address, opening_balance))
                    conn.commit()
                    flash("Party created successfully!", "success")
                    conn.close()
                    return redirect(url_for("parties"))
        except ValueError:
            flash("Invalid Opening Balance amount.", "error")
    party_list = conn.execute("SELECT * FROM parties ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("parties.html", parties=party_list)


@app.route("/parties/delete/<int:id>")
def delete_party(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("DELETE FROM parties WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Party deleted successfully!", "success")
    return redirect(url_for("parties"))


@app.route("/parties/edit/<int:id>", methods=["GET", "POST"])
def edit_party(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    if request.method == "POST":
        party_name = request.form.get("party_name", "").strip()
        party_type = request.form.get("party_type", "Debtor")
        contact_number = request.form.get("contact_number", "").strip()
        email = request.form.get("email", "").strip()
        gstin = request.form.get("gstin", "").strip()
        address = request.form.get("address", "").strip()
        try:
            opening_balance = float(request.form.get("opening_balance") or 0)

            existing = conn.execute("SELECT id FROM parties WHERE (party_name = ? OR gstin = ?) AND id != ?", (party_name, gstin, id)).fetchone()

            if existing:
                flash(f"Error: Party Name '{party_name}' or GSTIN '{gstin}' already exists in another record!", "error")
            else:
                conn.execute("UPDATE parties SET party_name=?, party_type=?, contact_number=?, email=?, gstin=?, address=?, opening_balance=? WHERE id=?", (party_name, party_type, contact_number, email, gstin, address, opening_balance, id))
                conn.commit()
                flash("Party updated successfully!", "success")
                conn.close()
                return redirect(url_for("parties"))
        except ValueError:
            flash("Invalid amount.", "error")
    party = conn.execute("SELECT * FROM parties WHERE id = ?", (id,)).fetchone()
    conn.close()
    return render_template("edit_party.html", party=party)


# ------------------------------------------------------------------
# LEDGERS
# ------------------------------------------------------------------
@app.route("/client_ledger")
def client_ledger():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    clients = conn.execute("SELECT DISTINCT paid_name as name FROM accounts WHERE transaction_type = 'Income' AND paid_name != '' AND paid_name IS NOT NULL UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type = 'Debtor' UNION SELECT DISTINCT client_name as name FROM projects").fetchall()

    selected_client = request.args.get("client", "")
    transactions = []
    opening_balance = 0
    total_debit = 0
    total_credit = 0
    closing_balance = 0

    if selected_client:
        party = conn.execute("SELECT opening_balance, address FROM parties WHERE party_name = ? AND party_type = 'Debtor'", (selected_client,)).fetchone()
        if party:
            opening_balance = party['opening_balance']

        bills = conn.execute("SELECT bill_date as date, 'Sales Bill (Inv: ' || bill_no || ')' as particulars, total_value as debit, 0 as credit FROM bills WHERE project_name IN (SELECT project_name FROM projects WHERE client_name = ?)", (selected_client,)).fetchall()
        payments = conn.execute("SELECT transaction_date as date, 'By ' || description as particulars, 0 as debit, amount as credit FROM accounts WHERE transaction_type = 'Income' AND paid_name = ?", (selected_client,)).fetchall()

        raw_txs = [dict(b) for b in bills] + [dict(p) for p in payments]
        raw_txs.sort(key=lambda x: x['date'] if x['date'] else '9999-12-31')

        running_balance = opening_balance
        total_debit = opening_balance
        total_credit = 0

        for tx in raw_txs:
            debit = tx['debit'] or 0
            credit = tx['credit'] or 0
            total_debit += debit
            total_credit += credit

            running_balance = running_balance + debit - credit
            tx['balance'] = running_balance
            transactions.append(tx)

        closing_balance = running_balance

    conn.close()
    return render_template("client_ledger.html", clients=clients, transactions=transactions, selected_client=selected_client, opening_balance=opening_balance, total_debit=total_debit, total_credit=total_credit, closing_balance=closing_balance)


@app.route("/vendor_ledger")
def vendor_ledger():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    vendors = conn.execute("SELECT DISTINCT supplier_name as name FROM purchases WHERE supplier_name != '' AND supplier_name IS NOT NULL UNION SELECT DISTINCT party_name as name FROM parties WHERE party_type = 'Creditor'").fetchall()

    selected_vendor = request.args.get("vendor", "")
    transactions = []
    opening_balance = 0
    total_po_value = 0
    total_bill_value = 0
    total_paid = 0
    closing_balance = 0

    if selected_vendor:
        party = conn.execute("SELECT opening_balance, address FROM parties WHERE party_name = ? AND party_type = 'Creditor'", (selected_vendor,)).fetchone()
        if party:
            opening_balance = party['opening_balance']

        pos_raw = conn.execute("""
            SELECT po.id, po.po_date as date, 'PO #' || po.id || ' (Order)' as particulars,
                   'PO' as type,
                   IFNULL(SUM(po_items.quantity * po_items.rate), 0) * 1.18 as po_value,
                   0 as bill_value, 0 as paid_amount
            FROM po
            JOIN po_items ON po.id = po_items.po_id
            WHERE po.vendor_name = ?
            GROUP BY po.id
        """, (selected_vendor,)).fetchall()

        bills_raw = conn.execute("""
            SELECT id, invoice_date as date, 'Purchase Bill (Inv: ' || invoice_number || ')' as particulars,
                   'Bill' as type,
                   0 as po_value, total_amount as bill_value, 0 as paid_amount
            FROM purchases WHERE supplier_name = ?
        """, (selected_vendor,)).fetchall()

        payments_raw = conn.execute("""
            SELECT id, transaction_date as date, 'Payment - ' || description as particulars,
                   'Payment' as type,
                   0 as po_value, 0 as bill_value, amount as paid_amount
            FROM accounts WHERE transaction_type = 'Expense' AND paid_name = ?
        """, (selected_vendor,)).fetchall()

        raw_txs = [dict(p) for p in pos_raw] + [dict(b) for b in bills_raw] + [dict(pay) for pay in payments_raw]
        raw_txs.sort(key=lambda x: x['date'] if x['date'] else '9999-12-31')

        running_balance = opening_balance
        for tx in raw_txs:
            if tx['type'] != 'PO':
                running_balance = running_balance + (tx['bill_value'] or 0) - (tx['paid_amount'] or 0)

            tx['balance'] = running_balance

            if tx['type'] == 'PO':
                total_po_value += tx['po_value'] or 0
            elif tx['type'] == 'Bill':
                total_bill_value += tx['bill_value'] or 0
            elif tx['type'] == 'Payment':
                total_paid += tx['paid_amount'] or 0

            transactions.append(tx)

        closing_balance = running_balance

    po_bill_diff = total_po_value - total_bill_value
    conn.close()

    return render_template("vendor_ledger.html",
                           vendors=vendors, transactions=transactions, selected_vendor=selected_vendor,
                           opening_balance=opening_balance, total_po_value=total_po_value,
                           total_bill_value=total_bill_value, total_paid=total_paid,
                           closing_balance=closing_balance, po_bill_diff=po_bill_diff)


# ------------------------------------------------------------------
# BOQ (POQ)
# ------------------------------------------------------------------
@app.route("/poq", methods=["GET", "POST"])
def poq():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    selected_project = request.args.get("project", "")
    edit_id = request.args.get("edit")

    if request.method == "POST":
        selected_project = request.form.get("project_name", "")
        edit_id = request.form.get("edit_id")

        try:
            cursor = conn.cursor()
            descriptions = request.form.getlist("item_description[]")
            units = request.form.getlist("unit[]")
            quantities = request.form.getlist("quantity[]")
            supply_rates = request.form.getlist("supply_rate[]")
            erection_rates = request.form.getlist("erection_rate[]")
            subcon_names = request.form.getlist("subcon_name[]")
            subcon_rates = request.form.getlist("subcon_rate[]")

            for i in range(len(descriptions)):
                item_name = descriptions[i].strip()
                if item_name:
                    existing = cursor.execute("SELECT id FROM poq WHERE project_name = ? AND material_name = ?", (selected_project, item_name)).fetchone()
                    if existing and str(existing['id']) != str(edit_id):
                        flash(f"Error: '{item_name}' already exists in this Project BOQ!", "error")
                        conn.close()
                        return redirect(url_for("poq", project=selected_project))

                    qty = float(quantities[i]) if quantities[i] else 0
                    s_rate = float(supply_rates[i]) if supply_rates[i] else 0
                    e_rate = float(erection_rates[i]) if erection_rates[i] else 0
                    s_name = subcon_names[i].strip() if i < len(subcon_names) and subcon_names[i] else ""
                    s_rate_con = float(subcon_rates[i]) if i < len(subcon_rates) and subcon_rates[i] else 0

                    unit_val = units[i]
                    total_rate = s_rate + e_rate
                    amt = round(qty * total_rate, 2)

                    if edit_id:
                        cursor.execute("""
                            UPDATE poq SET material_name=?, unit=?, quantity=?, rate=?, amount=?, supply_rate=?, erection_rate=?, subcon_name=?, subcon_rate=?
                            WHERE id=?
                        """, (item_name, unit_val, qty, total_rate, amt, s_rate, e_rate, s_name, s_rate_con, edit_id))
                        flash("BOQ Item updated successfully!", "success")
                    else:
                        cursor.execute("""
                            INSERT INTO poq (project_name, material_name, unit, quantity, rate, amount, supply_rate, erection_rate, subcon_name, subcon_rate)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (selected_project, item_name, unit_val, qty, total_rate, amt, s_rate, e_rate, s_name, s_rate_con))

                        existing_stock = cursor.execute("SELECT id FROM stock WHERE material_name = ?", (item_name,)).fetchone()
                        if not existing_stock:
                            cursor.execute("INSERT INTO stock (material_name, unit, opening_stock) VALUES (?, ?, 0)", (item_name, unit_val))

            conn.commit()
            if not edit_id:
                flash("BOQ Items added successfully!", "success")
        except Exception as e:
            flash(f"Error: {str(e)}", "error")

        conn.close()
        return redirect(url_for("poq", project=selected_project))

    project_list = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    boq_list = []
    total_boq_value = 0
    edit_boq_data = None

    if edit_id:
        edit_boq_data = conn.execute("SELECT * FROM poq WHERE id = ?", (edit_id,)).fetchone()

    if selected_project:
        boq_list = conn.execute("SELECT * FROM poq WHERE project_name = ? ORDER BY id ASC", (selected_project,)).fetchall()
        total_boq_value = sum((item['amount'] or 0) for item in boq_list)

    conn.close()
    return render_template("poq.html", project_list=project_list, selected_project=selected_project, boq_list=boq_list, total_boq_value=total_boq_value, edit_boq_data=edit_boq_data)


@app.route("/poq/delete/<int:id>")
def delete_poq(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    project_name = request.args.get("project", "")
    conn = get_db()
    conn.execute("DELETE FROM poq WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("BOQ Item deleted successfully!", "success")
    return redirect(url_for("poq", project=project_name))


# ------------------------------------------------------------------
# WORK PROGRESS (UPDATED WITH EDIT/DELETE)
# ------------------------------------------------------------------
@app.route("/work_progress", methods=["GET", "POST"])
def work_progress():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()
    selected_project = request.args.get("project", "")

    if request.method == "POST":
        boq_item_id = request.form.get("boq_item_id")
        work_date = request.form.get("work_date")
        qty_supply = float(request.form.get("qty_supply") or 0)
        qty_erection = float(request.form.get("qty_erection") or 0)
        remarks = request.form.get("remarks", "")

        if boq_item_id and (qty_supply > 0 or qty_erection > 0):
            conn.execute("""
                INSERT INTO work_progress (project_name, boq_item_id, work_date, qty_supply, qty_erection, remarks)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (selected_project, boq_item_id, work_date, qty_supply, qty_erection, remarks))
            conn.commit()
            flash("Work progress updated successfully!", "success")

        conn.close()
        return redirect(url_for("work_progress", project=selected_project))

    project_list = conn.execute("SELECT * FROM projects ORDER BY project_name").fetchall()
    boq_progress_list = []
    work_history = []

    if selected_project:
        boq_items = conn.execute("SELECT * FROM poq WHERE project_name = ? ORDER BY id ASC", (selected_project,)).fetchall()

        for item in boq_items:
            done_supply = conn.execute("SELECT SUM(qty_supply) FROM work_progress WHERE boq_item_id = ?", (item['id'],)).fetchone()[0] or 0
            done_erection = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id = ?", (item['id'],)).fetchone()[0] or 0

            billed_supply = conn.execute("SELECT SUM(qty_supply) FROM work_progress WHERE boq_item_id = ? AND is_billed_supply = 1", (item['id'],)).fetchone()[0] or 0
            billed_erection = conn.execute("SELECT SUM(qty_erection) FROM work_progress WHERE boq_item_id = ? AND is_billed_erection = 1", (item['id'],)).fetchone()[0] or 0

            total_qty = item['quantity'] or 0

            boq_progress_list.append({
                "id": item['id'],
                "description": item['material_name'],
                "unit": item['unit'],
                "total_qty": total_qty,
                "done_supply": done_supply,
                "done_erection": done_erection,
                "balance_supply": total_qty - done_supply,
                "balance_erection": total_qty - done_erection,
                "billed_supply": billed_supply,
                "billed_erection": billed_erection,
                "supply_rate": item['supply_rate'] or 0,
                "erection_rate": item['erection_rate'] or 0,
            })

        work_history_raw = conn.execute("""
            SELECT wp.id, wp.work_date, bq.material_name, wp.qty_supply, wp.qty_erection, wp.remarks, wp.is_billed_supply, wp.is_billed_erection 
            FROM work_progress wp
            JOIN poq bq ON wp.boq_item_id = bq.id
            WHERE wp.project_name = ?
            ORDER BY wp.work_date DESC, wp.id DESC
        """, (selected_project,)).fetchall()
        work_history = [dict(row) for row in work_history_raw]

    conn.close()
    return render_template("work_progress.html",
                           project_list=project_list,
                           selected_project=selected_project,
                           boq_progress_list=boq_progress_list,
                           work_history=work_history)


@app.route("/work_progress/delete/<int:id>")
def delete_work_progress(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    project_name = request.args.get("project", "")
    
    conn = get_db()
    wp = conn.execute("SELECT * FROM work_progress WHERE id = ?", (id,)).fetchone()
    
    if wp:
        if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1:
            flash("Cannot delete: This work is already billed in an RA Bill.", "error")
        else:
            conn.execute("DELETE FROM work_progress WHERE id = ?", (id,))
            conn.commit()
            flash("Work progress entry deleted successfully!", "success")
    else:
        flash("Entry not found!", "error")
        
    conn.close()
    return redirect(url_for("work_progress", project=project_name))


@app.route("/work_progress/edit/<int:id>", methods=["GET", "POST"])
def edit_work_progress(id):
    if not session.get("username"):
        return redirect(url_for("login"))
        
    conn = get_db()
    wp = conn.execute("SELECT * FROM work_progress WHERE id = ?", (id,)).fetchone()
    
    if not wp:
        flash("Entry not found!", "error")
        conn.close()
        return redirect(url_for("work_progress"))
        
    if wp['is_billed_supply'] == 1 or wp['is_billed_erection'] == 1:
        flash("Cannot edit: This work is already billed in an RA Bill.", "error")
        conn.close()
        return redirect(url_for("work_progress", project=wp['project_name']))

    if request.method == "POST":
        work_date = request.form.get("work_date")
        qty_supply = float(request.form.get("qty_supply") or 0)
        qty_erection = float(request.form.get("qty_erection") or 0)
        remarks = request.form.get("remarks", "")
        
        conn.execute("""
            UPDATE work_progress SET work_date=?, qty_supply=?, qty_erection=?, remarks=? WHERE id=?
        """, (work_date, qty_supply, qty_erection, remarks, id))
        conn.commit()
        conn.close()
        flash("Work progress updated successfully!", "success")
        return redirect(url_for("work_progress", project=wp['project_name']))

    boq_item = conn.execute("SELECT * FROM poq WHERE id = ?", (wp['boq_item_id'],)).fetchone()
    conn.close()
    
    return render_template("edit_work_progress.html", wp=wp, boq_item=boq_item)


@app.route("/generate_ra_bill/<project_name>")
def generate_ra_bill(project_name):
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = get_db()

    try:
        cursor = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")

        unbilled_supply = conn.execute("""
            SELECT wp.id, bq.material_name, bq.supply_rate, wp.qty_supply
            FROM work_progress wp
            JOIN poq bq ON wp.boq_item_id = bq.id
            WHERE wp.project_name = ? AND wp.is_billed_supply = 0 AND wp.qty_supply > 0
        """, (project_name,)).fetchall()

        if unbilled_supply:
            bill_no_sup = f"RA-SUP-{project_name[:3].upper()}-{datetime.now().strftime('%m%d%H%M')}"
            total_val_sup = round(sum(w['qty_supply'] * w['supply_rate'] for w in unbilled_supply))

            cursor.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value) VALUES (?, ?, ?, ?)", (project_name, bill_no_sup, today, total_val_sup))
            bill_id_sup = cursor.lastrowid

            for w in unbilled_supply:
                amt = w['qty_supply'] * w['supply_rate']
                cursor.execute("""
                    INSERT INTO bill_items (bill_id, description, quantity, rate, supply_rate, erection_rate, basic_amount, total_amount)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (bill_id_sup, f"[Supply] {w['material_name']}", w['qty_supply'], w['supply_rate'], w['supply_rate'], 0, amt, amt))
                cursor.execute("UPDATE work_progress SET is_billed_supply = 1 WHERE id = ?", (w['id'],))

            flash(f"Supply Bill ({bill_no_sup}) generated: ₹{total_val_sup:.2f}", "success")

        unbilled_erection = conn.execute("""
            SELECT wp.id, bq.material_name, bq.erection_rate, wp.qty_erection
            FROM work_progress wp
            JOIN poq bq ON wp.boq_item_id = bq.id
            WHERE wp.project_name = ? AND wp.is_billed_erection = 0 AND wp.qty_erection > 0
        """, (project_name,)).fetchall()

        if unbilled_erection:
            bill_no_ere = f"RA-ERE-{project_name[:3].upper()}-{datetime.now().strftime('%m%d%H%M')}"
            total_val_ere = round(sum(w['qty_erection'] * w['erection_rate'] for w in unbilled_erection))

            cursor.execute("INSERT INTO bills (project_name, bill_no, bill_date, total_value) VALUES (?, ?, ?, ?)", (project_name, bill_no_ere, today, total_val_ere))
            bill_id_ere = cursor.lastrowid

            for w in unbilled_erection:
                amt = w['qty_erection'] * w['erection_rate']
                cursor.execute("""
                    INSERT INTO bill_items (bill_id, description, quantity, rate, supply_rate, erection_rate, basic_amount, total_amount)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (bill_id_ere, f"[Erection] {w['material_name']}", w['qty_erection'], w['erection_rate'], 0, w['erection_rate'], amt, amt))
                cursor.execute("UPDATE work_progress SET is_billed_erection = 1 WHERE id = ?", (w['id'],))

            flash(f"Erection Bill ({bill_no_ere}) generated: ₹{total_val_ere:.2f}", "success")

        if not unbilled_supply and not unbilled_erection:
            flash("No unbilled supply or erection work found.", "error")

        conn.commit()
    except Exception as e:
        flash(f"Error: {str(e)}", "error")

    conn.close()
    return redirect(url_for("accounts_entry", project=project_name))


# ------------------------------------------------------------------
# PURCHASE ORDERS
# ------------------------------------------------------------------
@app.route("/po", methods=["GET", "POST"])
def po():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        project_name = request.form.get("project_name")
        vendor_name = request.form.get("vendor_name")
        po_date = request.form.get("po_date")
        delivery_address = request.form.get("delivery_address")
        quotation_no = request.form.get("quotation_no")
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO po (project_name, vendor_name, po_date, delivery_address, quotation_no, gm_approval) VALUES (?, ?, ?, ?, ?, 'Pending')", (project_name, vendor_name, po_date, delivery_address, quotation_no))
            po_id = cursor.lastrowid
            material_names = request.form.getlist("material_name[]")
            hsn_codes = request.form.getlist("hsn_code[]")
            quantities = request.form.getlist("quantity[]")
            units = request.form.getlist("unit[]")
            rates = request.form.getlist("rate[]")

            for i in range(len(material_names)):
                if material_names[i].strip():
                    qty = float(quantities[i]) if quantities[i] else 0
                    rt = float(rates[i]) if rates[i] else 0
                    cursor.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate) VALUES (?, ?, ?, ?, ?, ?)", (po_id, material_names[i], hsn_codes[i], qty, units[i], rt))
            conn.commit()
            flash("Purchase Order created successfully! Waiting for GM Approval.", "success")
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
        conn.close()
        return redirect(url_for("po"))

    po_list = conn.execute("SELECT * FROM po ORDER BY id DESC").fetchall()
    po_with_total = []
    for p in po_list:
        items = conn.execute("SELECT quantity, rate FROM po_items WHERE po_id = ?", (p['id'],)).fetchall()
        base_total = sum((i['quantity'] or 0) * (i['rate'] or 0) for i in items)
        total_with_gst = round(base_total * 1.18, 2)
        p_dict = dict(p)
        p_dict['total'] = total_with_gst
        po_with_total.append(p_dict)

    project_list = conn.execute("SELECT project_name FROM projects").fetchall()
    vendors = conn.execute("SELECT party_name FROM parties WHERE party_type = 'Creditor'").fetchall()
    materials = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close()
    return render_template("po.html", po_list=po_with_total, project_list=project_list, vendors=vendors, materials=materials)


@app.route("/po/edit/<int:id>", methods=["GET", "POST"])
def edit_po(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        project_name = request.form.get("project_name")
        vendor_name = request.form.get("vendor_name")
        po_date = request.form.get("po_date")
        delivery_address = request.form.get("delivery_address")
        quotation_no = request.form.get("quotation_no")

        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE po SET project_name=?, vendor_name=?, po_date=?, delivery_address=?, quotation_no=? WHERE id=?
            """, (project_name, vendor_name, po_date, delivery_address, quotation_no, id))

            cursor.execute("DELETE FROM po_items WHERE po_id = ?", (id,))

            material_names = request.form.getlist("material_name[]")
            hsn_codes = request.form.getlist("hsn_code[]")
            quantities = request.form.getlist("quantity[]")
            units = request.form.getlist("unit[]")
            rates = request.form.getlist("rate[]")

            for i in range(len(material_names)):
                if material_names[i].strip():
                    qty = float(quantities[i]) if quantities[i] else 0
                    rt = float(rates[i]) if rates[i] else 0
                    cursor.execute("INSERT INTO po_items (po_id, material_name, hsn_code, quantity, unit, rate) VALUES (?, ?, ?, ?, ?, ?)", (id, material_names[i], hsn_codes[i], qty, units[i], rt))

            conn.commit()
            flash("Purchase Order updated successfully!", "success")
            conn.close()
            return redirect(url_for("po"))
        except Exception as e:
            flash(f"Error: {str(e)}", "error")

    po_data = conn.execute("SELECT * FROM po WHERE id = ?", (id,)).fetchone()
    items = conn.execute("SELECT * FROM po_items WHERE po_id = ?", (id,)).fetchall()
    project_list = conn.execute("SELECT project_name FROM projects").fetchall()
    vendors = conn.execute("SELECT party_name FROM parties WHERE party_type = 'Creditor'").fetchall()
    materials = conn.execute("SELECT material_name, unit FROM stock").fetchall()
    conn.close()

    if not po_data:
        flash("PO not found!", "error")
        return redirect(url_for("po"))

    return render_template("edit_po.html", po=po_data, items=items, project_list=project_list, vendors=vendors, materials=materials)


@app.route("/po/print/<int:id>")
def print_po(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    po_data = conn.execute("SELECT * FROM po WHERE id = ?", (id,)).fetchone()
    items = conn.execute("SELECT * FROM po_items WHERE po_id = ?", (id,)).fetchall()

    if not po_data:
        flash("PO not found!", "error")
        conn.close()
        return redirect(url_for("po"))

    vendor_data = conn.execute("SELECT * FROM parties WHERE party_name = ? AND party_type = 'Creditor'", (po_data['vendor_name'],)).fetchone()
    conn.close()

    vendor_gstin = vendor_data['gstin'] if vendor_data and vendor_data['gstin'] else ''
    is_intra_state = vendor_gstin.startswith('33')

    sub_total = 0.0
    for item in items:
        try:
            qty = float(item['quantity']) if item['quantity'] else 0.0
            rate = float(item['rate']) if item['rate'] else 0.0
            sub_total += (qty * rate)
        except (ValueError, TypeError):
            pass

    total_gst = round(sub_total * 0.18, 2)

    if is_intra_state:
        cgst = round(total_gst / 2, 2)
        sgst = round(total_gst / 2, 2)
        igst = 0.0
    else:
        cgst = 0.0
        sgst = 0.0
        igst = total_gst

    grand_total = round(sub_total + total_gst, 2)

    return render_template("print_po.html",
                           po=po_data, items=items, vendor=vendor_data,
                           sub_total=sub_total, cgst=cgst, sgst=sgst, igst=igst,
                           total_gst=total_gst, grand_total=grand_total,
                           is_intra_state=is_intra_state)


# ------------------------------------------------------------------
# GM APPROVAL
# ------------------------------------------------------------------
@app.route("/gm_approval")
def gm_approval():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    pending_pos = conn.execute("SELECT * FROM po WHERE gm_approval = 'Pending' ORDER BY id DESC").fetchall()
    approved_pos = conn.execute("SELECT * FROM po WHERE gm_approval = 'Approved' ORDER BY id DESC").fetchall()

    pending_with_total = []
    for p in pending_pos:
        items = conn.execute("SELECT quantity, rate FROM po_items WHERE po_id = ?", (p['id'],)).fetchall()
        base_total = sum((i['quantity'] or 0) * (i['rate'] or 0) for i in items)
        total_with_gst = round(base_total * 1.18, 2)
        p_dict = dict(p)
        p_dict['total'] = total_with_gst
        pending_with_total.append(p_dict)

    conn.close()
    return render_template("gm_approval.html", pending=pending_with_total, approved=approved_pos)


@app.route("/gm_approve/<int:id>")
def gm_approve(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE po SET gm_approval = 'Approved' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("PO Approved successfully! Now you can make Purchases.", "success")
    return redirect(url_for("gm_approval"))


# ------------------------------------------------------------------
# GST RECONCILIATION
# ------------------------------------------------------------------
@app.route("/gst_reconciliation", methods=["GET", "POST"])
def gst_reconciliation():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    if request.method == "POST":
        file = request.files.get('file')
        if file and file.filename != '':
            conn.execute("DELETE FROM gstr2b_data")
            try:
                df = pd.read_excel(file)
                required = {'Invoice Number', 'Trade/Legal Name', 'Total'}
                if not required.issubset(df.columns):
                    flash(f"Uploaded file is missing required columns: {required - set(df.columns)}", "error")
                else:
                    for index, row in df.iterrows():
                        inv_no = str(row.get('Invoice Number', ''))
                        supp = str(row.get('Trade/Legal Name', ''))
                        val = float(row.get('Total', 0))

                        conn.execute("""
                            INSERT INTO gstr2b_data (supplier_name, invoice_number, total_value)
                            VALUES (?, ?, ?)
                        """, (supp, inv_no, val))
                    conn.commit()
                    flash("GSTR-2B Uploaded! Click Run Reconcile.", "success")
            except Exception as e:
                flash(f"Error: {str(e)}", "error")
        conn.close()
        return redirect(url_for("gst_reconciliation"))

    uploaded_data = conn.execute("SELECT * FROM gstr2b_data ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("gst_reconciliation.html", uploaded_data=uploaded_data)


@app.route("/run_reconciliation")
def run_reconciliation():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    uploaded_data = conn.execute("SELECT * FROM gstr2b_data").fetchall()

    for row in uploaded_data:
        purchase = conn.execute("SELECT total_amount FROM purchases WHERE invoice_number = ?", (row['invoice_number'],)).fetchone()

        if purchase:
            if abs((purchase['total_amount'] or 0) - (row['total_value'] or 0)) < 0.01:
                conn.execute("UPDATE gstr2b_data SET match_status = 'Matched' WHERE id = ?", (row['id'],))
            else:
                conn.execute("UPDATE gstr2b_data SET match_status = 'Amount Mismatch' WHERE id = ?", (row['id'],))
        else:
            conn.execute("UPDATE gstr2b_data SET match_status = 'Missing in Purchase' WHERE id = ?", (row['id'],))

    conn.commit()
    conn.close()
    flash("Reconciliation Completed!", "success")
    return redirect(url_for("gst_reconciliation"))


# ------------------------------------------------------------------
# MD APPROVAL
# ------------------------------------------------------------------
@app.route("/md_approval")
def md_approval():
    if not session.get("username"):
        return redirect(url_for("login"))

    conn = None
    try:
        conn = get_db()
        pending = conn.execute("SELECT * FROM purchases WHERE md_approval = 'Pending' ORDER BY id DESC").fetchall()

        pending_with_progress = []
        for p in pending:
            p_dict = dict(p)
            proj_name = p_dict.get('project_name', '')

            try:
                boq_row = conn.execute("SELECT SUM(amount) FROM poq WHERE project_name = ?", (proj_name,)).fetchone()
                boq_val = boq_row[0] if boq_row and boq_row[0] else 0
            except: boq_val = 0

            try:
                done_row = conn.execute("""
                    SELECT SUM(
                        (IFNULL(wp.qty_supply,0) * IFNULL(bq.supply_rate,0)) +
                        (IFNULL(wp.qty_erection,0) * IFNULL(bq.erection_rate,0))
                    )
                    FROM work_progress wp
                    JOIN poq bq ON wp.boq_item_id = bq.id
                    WHERE wp.project_name = ?
                """, (proj_name,)).fetchone()
                done_val = done_row[0] if done_row and done_row[0] else 0
            except: done_val = 0

            progress_pct = (done_val / boq_val * 100) if boq_val > 0 else 0

            p_dict['boq_value'] = boq_val
            p_dict['done_value'] = done_val
            p_dict['progress_pct'] = round(progress_pct, 1)

            pending_with_progress.append(p_dict)

        approved = conn.execute("SELECT * FROM purchases WHERE md_approval = 'Approved' ORDER BY id DESC").fetchall()
        conn.close()

        return render_template("md_approval.html", pending=pending_with_progress, approved=approved)
    except Exception as e:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        print(f"MD approval route error: {e}")
        flash("A database error occurred while loading approvals.", "error")
        return redirect(url_for("dashboard"))


@app.route("/md_approve/<int:id>")
def md_approve(id):
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("UPDATE purchases SET md_approval = 'Approved' WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Bill Approved for Payment!", "success")
    return redirect(url_for("md_approval"))


# ------------------------------------------------------------------
# REPORTS & CSV EXPORT
# ------------------------------------------------------------------
@app.route("/reports", methods=["GET"])
def reports():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()
    selected_project = request.args.get("project", "")
    selected_month = request.args.get("month", "")

    if selected_project:
        projects = conn.execute("SELECT * FROM projects WHERE project_name = ?", (selected_project,)).fetchall()
    else:
        projects = conn.execute("SELECT * FROM projects").fetchall()

    total_order_value = sum((p['project_value'] or 0) for p in projects)

    purchase_query = "SELECT * FROM purchases WHERE 1=1"
    purchase_params = []
    if selected_project:
        purchase_query += " AND project_name = ?"
        purchase_params.append(selected_project)
    if selected_month:
        purchase_query += " AND strftime('%Y-%m', invoice_date) = ?"
        purchase_params.append(selected_month)
    purchase_list = conn.execute(purchase_query + " ORDER BY id DESC", purchase_params).fetchall()
    total_purchase_value = sum(p['total_amount'] for p in purchase_list)

    bill_query = "SELECT * FROM bills WHERE 1=1"
    bill_params = []
    if selected_project:
        bill_query += " AND project_name = ?"
        bill_params.append(selected_project)
    if selected_month:
        bill_query += " AND strftime('%Y-%m', bill_date) = ?"
        bill_params.append(selected_month)
    bills_list = conn.execute(bill_query + " ORDER BY id DESC", bill_params).fetchall()
    total_sales_value = sum(b['total_value'] for b in bills_list)

    project_list = conn.execute("SELECT project_name FROM projects").fetchall()
    conn.close()

    return render_template("reports.html",
                           projects=projects, purchase_list=purchase_list,
                           bills_list=bills_list, project_list=project_list,
                           selected_project=selected_project, selected_month=selected_month,
                           total_order_value=total_order_value, total_purchase_value=total_purchase_value,
                           total_sales_value=total_sales_value)


@app.route("/reports/export/csv")
def reports_export_csv():
    if not session.get("username"):
        return redirect(url_for("login"))

    if session.get("role") == "Site Supervisor":
        flash("Access Denied: You don't have permission to export reports.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    selected_project = request.args.get("project", "")
    selected_month = request.args.get("month", "")

    pq = "SELECT * FROM purchases WHERE 1=1"
    pq_params = []
    if selected_project:
        pq += " AND project_name = ?"
        pq_params.append(selected_project)
    if selected_month:
        pq += " AND strftime('%Y-%m', invoice_date) = ?"
        pq_params.append(selected_month)
    purchase_list = conn.execute(pq + " ORDER BY invoice_date", pq_params).fetchall()

    bq = "SELECT * FROM bills WHERE 1=1"
    bq_params = []
    if selected_project:
        bq += " AND project_name = ?"
        bq_params.append(selected_project)
    if selected_month:
        bq += " AND strftime('%Y-%m', bill_date) = ?"
        bq_params.append(selected_month)
    bills_list = conn.execute(bq + " ORDER BY bill_date", bq_params).fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["PURCHASES (INVOICES)"])
    writer.writerow(["Date", "Invoice No", "Project", "Vendor", "Amount (Rs)"])
    total_purchase = 0
    for p in purchase_list:
        amt = p['total_amount'] or 0
        total_purchase += amt
        writer.writerow([
            p['invoice_date'] or "",
            p['invoice_number'] or "",
            p['project_name'] or "",
            p['supplier_name'] or "",
            f"{amt:.2f}"
        ])
    writer.writerow(["", "", "", "TOTAL", f"{total_purchase:.2f}"])
    writer.writerow([])

    writer.writerow(["SALES BILLS (CLIENT INVOICES)"])
    writer.writerow(["Date", "Bill No", "Project", "Amount (Rs)"])
    total_bills = 0
    for b in bills_list:
        amt = b['total_value'] or 0
        total_bills += amt
        writer.writerow([
            b['bill_date'] or "",
            b['bill_no'] or "",
            b['project_name'] or "",
            f"{amt:.2f}"
        ])
    writer.writerow(["", "", "TOTAL", f"{total_bills:.2f}"])
    writer.writerow([])

    writer.writerow(["SUMMARY"])
    writer.writerow(["Filter Project", selected_project or "All Projects"])
    writer.writerow(["Filter Month", selected_month or "All Months"])
    writer.writerow(["Total Purchase", f"{total_purchase:.2f}"])
    writer.writerow(["Total Sales", f"{total_bills:.2f}"])
    writer.writerow(["Net Difference", f"{total_bills - total_purchase:.2f}"])

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    filename = f"GOMS_Reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


@app.route("/vendor_report")
def vendor_report():
    if not session.get("username"):
        return redirect(url_for("login"))
    conn = get_db()

    selected_project = request.args.get("project", "")

    if selected_project:
        pairs = conn.execute("""
            SELECT DISTINCT project_name, vendor_name FROM po WHERE project_name = ?
            UNION
            SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases WHERE project_name = ?
        """, (selected_project, selected_project)).fetchall()
        proj_row = conn.execute("SELECT SUM(project_value) FROM projects WHERE project_name = ?", (selected_project,)).fetchone()
        total_proj_val = proj_row[0] if proj_row and proj_row[0] else 0
    else:
        pairs = conn.execute("""
            SELECT DISTINCT project_name, vendor_name FROM po
            UNION
            SELECT DISTINCT project_name, supplier_name as vendor_name FROM purchases
        """).fetchall()
        proj_row = conn.execute("SELECT SUM(project_value) FROM projects").fetchone()
        total_proj_val = proj_row[0] if proj_row and proj_row[0] else 0

    total_proj_val_gst = round(total_proj_val * 1.18, 2)

    report_data = []
    grand_po = 0
    grand_purchase = 0
    grand_paid = 0
    grand_diff = 0
    grand_payable = 0

    for pair in pairs:
        p_name = pair['project_name']
        v_name = pair['vendor_name']
        if not p_name or not v_name: continue

        po_val = conn.execute("""
            SELECT SUM(po_items.quantity * po_items.rate * 1.18)
            FROM po JOIN po_items ON po.id = po_items.po_id
            WHERE po.project_name = ? AND po.vendor_name = ?
        """, (p_name, v_name)).fetchone()[0] or 0

        purchase_val = conn.execute("SELECT SUM(total_amount) FROM purchases WHERE project_name = ? AND supplier_name = ?", (p_name, v_name)).fetchone()[0] or 0
        paid_val = conn.execute("SELECT SUM(amount) FROM accounts WHERE project_name = ? AND transaction_type = 'Expense' AND paid_name = ?", (p_name, v_name)).fetchone()[0] or 0

        diff = po_val - purchase_val
        balance_payable = purchase_val - paid_val

        report_data.append({
            "project": p_name, "vendor": v_name, "po": po_val,
            "purchase": purchase_val, "paid": paid_val, "diff": diff,
            "balance_payable": balance_payable
        })

        grand_po += po_val
        grand_purchase += purchase_val
        grand_paid += paid_val
        grand_diff += diff
        grand_payable += balance_payable

    pl_amount = total_proj_val_gst - grand_po

    project_list = conn.execute("SELECT project_name FROM projects ORDER BY project_name").fetchall()
    conn.close()

    return render_template("vendor_report.html", report_data=report_data, project_list=project_list, selected_project=selected_project,
                           total_proj_val_gst=total_proj_val_gst, pl_amount=pl_amount,
                           grand_po=grand_po, grand_purchase=grand_purchase,
                           grand_paid=grand_paid, grand_diff=grand_diff, grand_payable=grand_payable)


# ------------------------------------------------------------------
# BACKUP / LOGOUT
# ------------------------------------------------------------------
@app.route("/backup")
def backup():
    if not session.get("username"):
        return redirect(url_for("login"))
    if os.path.exists(DATABASE):
        date_str = datetime.now().strftime("%Y-%m-%d_%H-%M")
        backup_name = f"GOMS_ERP_Backup_{date_str}.db"
        return send_file(DATABASE, as_attachment=True, download_name=backup_name)
    else:
        flash("Database file not found!", "error")
        return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    print("--------------------------------")
    print("GOMS ELECTRICALS PVT LTD ERP")
    print("--------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
