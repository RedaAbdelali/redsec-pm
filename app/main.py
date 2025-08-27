import os
import secrets
import string
import base64
import getpass
from typing import Optional, Tuple, Dict, Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from supabase import create_client

# ---------------- CONFIG ----------------
SUPABASE_URL = "https://qnngbikchksjkudneyla.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFubmdiaWtjaGtzamt1ZG5leWxhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTU5NjIwMDgsImV4cCI6MjA3MTUzODAwOH0.hlOQu30fFgKWGkRWWjGffCChS9X_XiquW5wy9oYJE6Q"
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- PASSWORD UTIL ----------------
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def new_kdf_salt(size: int = 16) -> bytes:
    return os.urandom(size)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def derive_key_scrypt(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_password(aes_key: bytes, plaintext_password: str) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext_password.encode("utf-8"), None)
    return f"{nonce.hex()}:{ct.hex()}"

def decrypt_password(aes_key: bytes, packed: str) -> str:
    nonce_hex, ct_hex = packed.split(":")
    aesgcm = AESGCM(aes_key)
    pt = aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
    return pt.decode("utf-8")

# ---------------- AUTH & DB ----------------
ph = PasswordHasher()

def create_user(username: str, master_password_hash: str, enc_salt_b64: str) -> Dict[str, Any]:
    return supabase.table("users").insert({
        "username": username,
        "master_password_hash": master_password_hash,
        "enc_salt": enc_salt_b64,
    }).execute().data[0]

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    res = supabase.table("users").select("*").eq("username", username).limit(1).execute()
    return res.data[0] if res.data else None

def register_user(username: str, master_password: str) -> str:
    if get_user_by_username(username):
        raise ValueError("Username already exists.")
    master_hash = ph.hash(master_password)
    enc_salt = new_kdf_salt(16)
    user = create_user(username, master_hash, b64e(enc_salt))
    return user["id"]

def login_and_derive_key(username: str, master_password: str) -> Optional[Tuple[str, bytes]]:
    user = get_user_by_username(username)
    if not user:
        return None
    try:
        ph.verify(user["master_password_hash"], master_password)
    except VerifyMismatchError:
        return None
    salt = b64d(user["enc_salt"])
    aes_key = derive_key_scrypt(master_password, salt)
    return user["id"], aes_key

def save_password(user_id: str, site_name: str, email: str, encrypted_password: str) -> None:
    supabase.table("passwords").insert({
        "user_id": user_id,
        "site_name": site_name,
        "username": email,
        "password_encrypted": encrypted_password
    }).execute()

def get_password_entry(user_id: str, site_name: str) -> Optional[Dict[str, Any]]:
    res = supabase.table("passwords").select("*").eq("user_id", user_id).eq("site_name", site_name).limit(1).execute()
    return res.data[0] if res.data else None

# ---------------- CLI ----------------
def add_new_password(user_id: str, aes_key: bytes):
    print("\n=== Add New Password ===")
    site = input("Site / Service name (e.g., facebook.com): ").strip()
    email = input("Email/username for this account: ").strip()
    pw = generate_password(20)
    print(f"Generated strong password: {pw}")
    enc = encrypt_password(aes_key, pw)
    save_password(user_id, site, email, enc)
    print("Saved! (Copy password manually)")

def retrieve_password(user_id: str, aes_key: bytes):
    print("\n=== Retrieve Password ===")
    site = input("Site / Service name: ").strip()
    entry = get_password_entry(user_id, site)
    if not entry:
        print("No entry found.")
        return
    pw = decrypt_password(aes_key, entry["password_encrypted"])
    print(f"Password for {site}: {pw} (Copy manually!)")

# ---------------- MAIN ----------------
def main():
    print("=== Welcome to RedSec-PM ===")
    while True:
        choice = input("\n(r)egister, (l)ogin, (q)uit: ").strip().lower()
        if choice == "q":
            print("Bye."); return
        if choice not in {"r","l"}:
            print("Invalid choice."); continue
        username = input("Username: ").strip()
        master = getpass.getpass("Master password: ")
        if choice == "r":
            try:
                register_user(username, master)
                print("Registered successfully! Now login.")
            except ValueError as e:
                print(f"Error: {e}")
            continue
        res = login_and_derive_key(username, master)
        if not res:
            print("Login failed."); continue
        user_id, aes_key = res; print("Login success.")
        while True:
            action = input("\n(a)dd, (g)et, (q)uit: ").strip().lower()
            if action == "a": add_new_password(user_id, aes_key)
            elif action == "g": retrieve_password(user_id, aes_key)
            elif action == "q": print("Logged out."); break
            else: print("Invalid option.")

if __name__ == "__main__":
    main()
