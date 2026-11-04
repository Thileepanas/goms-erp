import sqlite3
import hashlib
import secrets

conn = sqlite3.connect('goms_erp_new.db')
password = "ChangeMe@123"
salt = secrets.token_hex(16)
password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()

conn.execute("UPDATE users SET salt = ?, password_hash = ? WHERE username = 'admin'", (salt, password_hash))
conn.commit()
conn.close()
print("✅ Admin password reset to: ChangeMe@123")