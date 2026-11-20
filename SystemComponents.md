Programming Languages

Python (3.11+): Core backend logic, routing, business rules, authentication flows, and security controls.

HTML5 & CSS3: Page structure and responsive layout for both desktop and mobile viewports.

JavaScript (ES6+): Minimal client-side interactivity—specifically needed for capturing keystroke timing intervals (Lab 4 behavioral detection) and invoking the browser's navigator.credentials WebAuthn API (Lab 5 passkeys).

SQL: Relational schema design and parameterized queries (managed via an ORM).

Frameworks & Core Libraries

Flask (Backend Web Framework): Handles HTTP routing, request/response lifecycles, and modular Blueprints (separating auth, shop, cart, checkout, and admin modules).

Jinja2 (Templating Engine): Built into Flask for server-side HTML rendering with automatic contextual HTML escaping (default XSS protection).

Bootstrap 5 (Frontend CSS Framework): Fast, responsive grid and UI components (navbars, product cards, forms, alerts) to satisfy the desktop/mobile usability requirement with minimal custom CSS.

SQLAlchemy / Flask-SQLAlchemy (ORM): Enforces parameterized queries (blocking SQL injection), manages database transactions (ACID compliance for store-credit checkout), and defines strict column constraints.

Database

PostgreSQL (Recommended) or SQLite: SQLite is fast to spin up for Phase 1 prototyping, while PostgreSQL is stronger for strict length/type enforcement (preventing silent truncation like Lab 2.2) and row-level locking during checkout.

Security & Authentication Components

Password Hashing: argon2-cffi or werkzeug.security (salted, slow hashing).

Session & CSRF Protection: Flask-Session (server-side session storage in Redis or the database so identity is never trusted from a client cookie) and Flask-WTF (anti-CSRF tokens and strict input validation).

Rate Limiting: Flask-Limiter to throttle login and 2FA OTP brute-force attempts.

2FA, TOTP & Passkeys: Python's built-in hmac/hashlib (or pyotp) for TOTP, and webauthn / cryptography (Ed25519) for FIDO2 passkey challenge verification.

Email Confirmation: Flask-Mail connected to a local SMTP trap like MailHog or Mailpit so your team can test registration confirmation links and 2FA emails offline without needing a real mail server.

Version Control & Testing

Git & GitHub: Required for tracking individual member commits across the Red and Blue teams.

Security Testing Tools: Burp Suite (Proxy, Repeater, Intruder) and Python requests scripts for self-testing and Red Team penetration testing.