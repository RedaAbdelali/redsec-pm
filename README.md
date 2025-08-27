# RedSec-PM 🔐

A minimal, secure, command-line **Password Manager** built with Python, Supabase, and Docker.  
Designed for personal use — simple, efficient, and safe.  

---

## ✨ Features
- 🔑 User registration & login with Argon2 password hashing  
- 🔒 Per-user AES-GCM encryption for stored passwords  
- 🗄️ Supabase Postgres backend (no RLS/policies needed for local personal use)  
- ⚡ Minimal & efficient codebase for easy learning/customization  
- 🐳 Dockerized setup for quick deployment  

---

## 📂 Project Structure
```bash
redsec-pm/
│── app/
│   └── main.py        # Main entry point (all logic merged here)
│── requirements.txt   # Python dependencies
│── Dockerfile         # Container build file
│── README.md          # Documentation
```

---

## 📦 Requirements
- [Docker](https://docs.docker.com/get-docker/)  
- (Optional) [Docker Compose](https://docs.docker.com/compose/) if you prefer

---

## ⚡ Getting Started
### 1. Clone the repo
```bash
git clone https://github.com/<your-username>/redsec-pm.git
cd redsec-pm
```
### 2. Configure Supabase
```bash
-- Enable pgcrypto so we can use gen_random_uuid()
create extension if not exists "pgcrypto";

-- Create users table
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  master_password_hash text not null,
  enc_salt text not null,
  created_at timestamp default now()
);

-- Create passwords table
create table if not exists passwords (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references users(id) on delete cascade,
  site_name text not null,
  username text,
  password_encrypted text not null,
  created_at timestamp default now()
);

-- Optional index for faster lookups by user + site
create index if not exists idx_passwords_user_site
  on passwords (user_id, site_name);
```
### 3. Update your Supabase URL and anon key in main.py:
```bash
SUPABASE_URL = "https://<your-project>.supabase.co"
SUPABASE_KEY = "<your-anon-key>"
```

---

## 🚀 Quickstart

### Run with Docker
```bash
# Build the image
docker build -t redsec-pm .

# Run the container
docker run -it --rm redsec-pm
```
### OR Run with Docker Compose (.yml)
```bash
version: "3.9"

services:
  redsec-pm:
    build: .
    container_name: redsec-pm
    stdin_open: true   # keep stdin open for getpass
    tty: true          # enable terminal input/output
```
then run:
```bash
docker-compose up --build
```
stop with:
```bash
docker-compose down
```
---

## 🖥️ Usage
After starting RedSec-PM:
```bash
=== Welcome to RedSec-PM ===

(r)egister, (l)ogin, (q)uit:
```

- Register → Create your account with a username & master password.
- Login → Enter credentials to unlock your vault.

### Session commands:
```bash
- (a)dd → Add new password (auto-generated).
- (g)et → Retrieve password for a site.
- (q)uit → Logout.
```
---

## 🔐 Security Notes

- Master password is never stored — only its Argon2 hash.
- Passwords are encrypted with AES-GCM, keys derived via scrypt.
- Supabase anon key is used (safe for personal/local use).
- This project is for educational and personal purposes only — not production-ready.

---

## 📜 License
MIT License © 2025 Reda Abdelali