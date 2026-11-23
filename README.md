# SecureShop — Hardened E-Commerce Web Application

> **Course:** CET431 – Software Security (Fall 2026)  
> **Institution:** Department of Computer Engineering Technology, Elsewedy University of Technology – Polytechnic of Egypt  
> **Scope:** Controlled Red Team / Blue Team E-Commerce Laboratory Application

**SecureShop** is a modular, defense-in-depth e-commerce web application built with **Python 3.11+**, **Flask**, **SQLAlchemy**, **Jinja2**, and **Bootstrap 5**. It implements all required e-commerce workflows (**FR-1** through **FR-7**) while embedding application-layer security controls (**SR-1** through **SR-8**) directly into the codebase to defend against every vulnerability class covered in the course ([Vulnerabilities.md](Vulnerabilities.md)).

---

## 1. Setup & Running Instructions

### Prerequisites
- **Python 3.11+** (verified on Python 3.12)
- **pip** (Python package manager)
- **Git** (optional, for cloning and version control)
- *(Optional)* **MailHog** or **Mailpit** on `localhost:1025` if you prefer inspecting SMTP traffic externally. **No external mail server is required**—SecureShop includes a built-in offline **Mail Outbox** (`/auth/outbox`).

### Step-by-Step Local Setup

1. **Navigate to the project directory:**
   ```bash
   cd SoftwareSecurity
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Core packages installed: `Flask`, `Flask-SQLAlchemy`, `SQLAlchemy`, `Werkzeug`, `Jinja2`, `bcrypt`, `cryptography`, and `itsdangerous`.

4. **Configure environment variables (optional):**
   The application runs out of the box with sensible defaults (SQLite in `instance/secureshop.db`). To customize secrets, database engine (e.g., PostgreSQL), SMTP settings, or security thresholds—including for future Docker containerization—copy `.env.example` and export the desired variables:
   ```bash
   # Reference template: .env.example
   SECRET_KEY=<strong-random-hex-key>
   DATABASE_URL=sqlite:///instance/secureshop.db   # or postgresql://user:pass@host:5432/secureshop
   HOST=0.0.0.0
   PORT=5000
   SESSION_COOKIE_SECURE=false                     # set true behind HTTPS/TLS
   ENFORCE_BUSINESS_HOURS=false                    # set true to enforce UTC login window
   ALLOWED_REGIONS=LOCAL,US-EAST,US-WEST,EU-WEST
   ```

5. **Start the application:**
   ```bash
   python run.py
   ```
   On first startup, the Flask application factory automatically creates all database tables (`db.create_all()`) and seeds default users, products, and coupons (`seed_initial_data()`).

6. **Access & verify:**
   - **Storefront:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
   - **Healthcheck endpoint (DevOps/Container ready):** [http://127.0.0.1:5000/healthz](http://127.0.0.1:5000/healthz) → `{"status": "ok"}`
   - **Offline Mail Outbox (Activation Links & 2FA OTPs):** [http://127.0.0.1:5000/auth/outbox](http://127.0.0.1:5000/auth/outbox)

7. **Resetting the database (clean slate):**
   Stop the server, delete `instance/secureshop.db`, and run `python run.py` again to regenerate a fresh seeded database.

---

## 2. Test Accounts & Pre-Seeded Data

Two verified accounts (a **normal customer** and an **administrator**) are automatically seeded on first launch (`secureshop/seed.py`). All passwords are stored exclusively as salted **bcrypt** (`rounds=12`) hashes—never in plaintext.

### Default Test Accounts

| Account Type | Role | Username | Email | Password | Initial Store Credit | Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **Normal User** | `customer` | `alice` | `alice@secureshop.local` | `CustomerPass123!` | `$750.00` | Verified, 2FA Enabled |
| **Administrator** | `admin` | `admin` | `admin@secureshop.local` | `AdminPass123!` | `$2,500.00` | Verified, 2FA Enabled |

### How to Sign In (2-Step MFA Flow)
1. Open **Login** (`/auth/login`) and submit either `alice` or `admin` credentials.
2. SecureShop transitions your session to `PENDING_2FA` and generates a single-use **6-digit OTP** (stored server-side as an HMAC-SHA256 hash).
3. Open the **Mail Outbox** tab (`/auth/outbox`) to read the 6-digit OTP (or use the user's RFC 6238 **TOTP** code shown on `/auth/verify-2fa`) and submit it to complete login and receive a server-tracked `UserSession`.

### Pre-Seeded Promotional Coupons & Catalogue Notes
- **Coupons:** `WELCOME10` (10% off, max 1 use/user — also issued via newsletter signup), `SAVE25` (`$25.00` fixed off, max 1 use/user), `VIP15` (15% off, max 2 uses/user).
- **Products:** 7 security-themed products across 5 categories, including 1 out-of-stock item (`USB Data Blocker & Power-Only Defender`) to demonstrate stock-availability filtering and checkout inventory checks.

---

## 3. One-Page Architecture Overview

### 3.1 High-Level System Architecture

```text
+--------------------------------------------------------------------------------------------------+
|  CLIENT (Desktop / Mobile Browser)                                                               |
|  Bootstrap 5 Responsive UI  |  Jinja2 Auto-Escaped HTML  |  security_telemetry.js (timing only)  |
+-----------------------------------------------+--------------------------------------------------+
                                                | HTTP / HTTPS (+ CSRF Token, HttpOnly Cookie)
                                                v
+--------------------------------------------------------------------------------------------------+
|  FLASK APPLICATION FACTORY  (secureshop/__init__.py + config.py)                                 |
|  [before_request] Global Rate Limit (429) -> Server Session Loader -> Anti-CSRF Validator (400)  |
|  [after_request]  CSP, HSTS, X-Frame-Options: DENY, nosniff, no-store, strip Server/X-Powered-By |
|  [errorhandlers]  Non-leaking custom templates (400, 403, 404, 429, 500) + DB rollback           |
+-----------------------------------------------+--------------------------------------------------+
                                                |
      +------------------+----------------------+----------------------+------------------+
      v                  v                      v                      v                  v
+------------+    +--------------+      +---------------+      +---------------+   +--------------+
|  auth_bp   |    |   shop_bp    |      |    cart_bp    |      |  checkout_bp  |   |  account_bp  |
|  /auth/*   |    | /, /product  |      |    /cart/*    |      |  /checkout/*  |   |  /account/*  |
| Reg, Verify|    | Search/Filter|      | Add/Update/Del|      | Coupon/Pay/   |   | Profile/Hist |
| MFA,Passkey|    | Newsletter   |      | Qty 1..99     |      | ACID Order SM |   | Isolated Pwd |
+------------+    | /datasheet   |      +---------------+      +---------------+   +--------------+
                  +--------------+                                                        |
                                            +--------------+                              |
                                            |   admin_bp   |  (Strict RBAC: role=='admin')|
                                            |   /admin/*   |  Users / Products / Coupons  |
                                            +--------------+                              |
                                                   |                                      |
                                                   v                                      v
+--------------------------------------------------------------------------------------------------+
|  SECURITY & BUSINESS LOGIC LAYER  (secureshop/utils.py)                                          |
|  - Strict RFC Validation (<=254 email)  - Authoritative Pricing & Coupon Caps (max 2 / <=50%)    |
|  - Ed25519 Passkey & No-Replay TOTP     - Behavioral Keystroke Z-Score & Poisoning Guard         |
|  - Server-IP Region & UTC Policy        - Relative-Only Redirects & Canonicalized File Paths     |
+-----------------------------------------------+--------------------------------------------------+
                                                | Parameterized SQLAlchemy ORM (ACID + Row Locks)
                                                v
+--------------------------------------------------------------------------------------------------+
|  PERSISTENCE & MESSAGING LAYER  (secureshop/models.py, extensions.py)                            |
|  SQLite (default) / PostgreSQL (via DATABASE_URL)  |  SMTP Relay (MailHog/Mailpit) + EmailOutbox |
+--------------------------------------------------------------------------------------------------+
```

### 3.2 Modular Codebase Layout

```text
SoftwareSecurity/
├── run.py                          # WSGI/dev entry point (HOST/PORT env-driven)
├── config.py                       # 12-factor environment config & security thresholds
├── requirements.txt                # Pinned Python dependencies
├── .env.example                    # Environment template (Docker/DevOps ready)
└── secureshop/
    ├── __init__.py                 # App factory, global CSRF/rate-limit guards, headers, error handlers
    ├── extensions.py               # Shared SQLAlchemy db instance
    ├── models.py                   # 12 ORM entities (bcrypt User, UserSession, WebAuthnCredential, etc.)
    ├── utils.py                    # Validators, MFA/TOTP/Ed25519, behavioral defense, cart/coupon engine
    ├── seed.py                     # Idempotent seeding for test accounts, catalogue, and coupons
    ├── blueprints/                 # Modular route controllers
    │   ├── auth.py                 # Registration, email confirm, 2FA, passkey challenge/verify, logout
    │   ├── shop.py                 # Catalogue, detail view, ORM search/filter, datasheet, newsletter
    │   ├── cart.py                 # Persistent server-side cart CRUD with quantity bounds
    │   ├── checkout.py             # Deduplicated coupon engine & ACID store-credit checkout state machine
    │   ├── account.py              # Allow-listed profile updates, isolated password change, order history
    │   └── admin.py                # Role-gated CRUD for users, products, and coupons
    ├── static/
    │   ├── css/styles.css          # Custom styling over Bootstrap 5
    │   └── js/security_telemetry.js# Privacy-preserving inter-keystroke timing collector (no raw chars)
    └── templates/                  # Auto-escaped Jinja2 templates (auth, shop, cart, checkout, account, admin, errors)
```

### 3.3 Core Data Model (12 Entities)
- **Identity & Auth:** `User` (bcrypt hash, role, store credit, lockouts, keystroke mean/std), `UserSession` (server-tracked opaque token + IP/UA binding), `WebAuthnCredential` (Ed25519 public key PEM + sign count), `SecurityAuditLog` (structured Blue Team alert trail).
- **Commerce & Transactions:** `Product` (authoritative price & stock), `CartItem` (user-bound cart lines), `Coupon` & `CouponUsage` (per-user & global redemption tracking), `NewsletterSubscriber`, `Order` (UUID + state machine `PENDING_PAYMENT -> PAID -> CONFIRMED`), `OrderItem` (immutable price snapshot), `EmailOutbox` (offline SMTP viewer).

### 3.4 Defense-in-Depth Control Mapping (Attack Surface Protection)

| Layer / Feature | Entry Points | Built-In Application Defenses |
| :--- | :--- | :--- |
| **Request Pipeline** | All routes (`__init__.py`) | Global IP sliding-window rate limiting (`429`), anti-CSRF tokens on every `POST/PUT/PATCH/DELETE` (`400`), strict `CSP`/`HSTS`/`X-Frame-Options: DENY`/`nosniff`/`no-store` headers, non-leaking `400/403/404/429/500` templates, `2 MB` payload cap, minimal `/robots.txt`. |
| **Auth, MFA & Passkeys** | `/auth/*` (`auth.py`) | Strict RFC email validation (`<= 254` chars, `400` on overflow—no silent truncation), bcrypt (`rounds=12`), per-account & IP lockouts, server-bound `PENDING_2FA -> AUTHENTICATED` state machine (no client `verify` cookie), hashed 6-digit single-use OTP + monotonic no-replay TOTP, single-use Ed25519 passkey challenges with strict `credential_id <-> user_id` binding, numeric-only keystroke timing analysis (baseline updated only after trusted MFA), server-socket IP region & UTC policy, `POST`-only logout. |
| **Catalogue & Files** | `/`, `/product/<id>`, `/datasheet/<file>`, `/newsletter/subscribe` (`shop.py`) | Parameterized SQLAlchemy ORM queries (blocks SQLi), Jinja2 contextual auto-escaping (blocks XSS), `safe_resolve_path()` canonicalization (blocks directory traversal), `safe_redirect_target()` relative-only redirects (blocks open redirects/phishing). |
| **Cart & Checkout** | `/cart/*`, `/checkout/*` (`cart.py`, `checkout.py`) | Authoritative server-side `Product.price` calculation (blocks price tampering), strict `1 <= qty <= 99` bounds (blocks negative totals & integer overflow), case-insensitive coupon set deduplication + `MAX_COUPONS_PER_ORDER=2` + `50%` cumulative cap (blocks alternating stacking & infinite money), ACID checkout with `with_for_update()` row locks, and `403` rejection on direct `/checkout/order-confirmation` bypasses. |
| **Account & Admin** | `/account/*`, `/admin/*` (`account.py`, `admin.py`) | Explicit editable field allow-list (blocks mass-assignment of `role`/`store_credit`), strict self-service isolation on `/account/change-password` with current-password verification and session rotation (blocks dual-use ATO), and explicit server-side `g.user.role == 'admin'` RBAC returning `403` (never trusts email substrings, cookies, or headers). |

---

## 4. Related Project Documents & Ethical Scope

- [Requirements.md](Requirements.md) — Complete Software Requirements Specification (`FR-1`–`FR-7`, `SR-1`–`SR-8`, `NFR-1`–`NFR-4`).
- [SystemComponents.md](SystemComponents.md) — Approved technology stack and security libraries.
- [Vulnerabilities.md](Vulnerabilities.md) — Master checklist of all 39 course threats & attacks verified against SecureShop.

> **Academic Ethics Notice:** Per CET431 course policy, all Red Team / Blue Team security testing must be conducted strictly against this local team-owned SecureShop instance within the authorized course environment. Never test external websites or unauthorized systems.
