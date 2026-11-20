import base64
import hashlib
import hmac
import secrets
import smtplib
import struct
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from email.message import EmailMessage
from functools import wraps
from flask import current_app, flash, g, redirect, request, session, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Coupon, EmaiOutbox if False else EmailOutbox, User, UserSession


def utcnow():
    return datetime.now(timezone.utc)


def generate_totp_secret() -> str:
    """Generates a 16-character Base32 secret compatible with RFC 6238 TOTP apps."""
    return base64.b32encode(secrets.token_bytes(10)).decode("utf-8")


def get_totp_token(secret: str, interval_offset: int = 0) -> str:
    """Computes a 6-digit RFC 6238 TOTP code using built-in hmac & hashlib."""
    try:
        key = base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
    except Exception:
        return "000000"
    counter = int(time.time() // 30) + interval_offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp_code(secret: str, candidate: str) -> bool:
    """Verifies a TOTP code allowing +/- 1 time step window."""
    if not secret or not candidate:
        return False
    candidate = candidate.strip()
    for offset in (-1, 0, 1):
        if hmac.compare_digest(get_totp_token(secret, offset), candidate):
            return True
    return False


# ==============================================================================
# Lab 3.11: Authentication Bypass via Encryption Oracle (Deterministic ECB Cipher)
# ==============================================================================
def _get_oracle_key_bytes() -> bytes:
    secret = current_app.config.get("SECRET_KEY", "secureshop-dev-secret")
    return hashlib.sha256(secret.encode("utf-8")).digest()[:16]


def oracle_encrypt_block(block16: bytes, key16: bytes) -> bytes:
    return bytes(b ^ k for b, k in zip(block16, key16))


def oracle_encrypt(plaintext: str) -> str:
    """
    Encrypts plaintext in deterministic 16-byte ECB blocks (PKCS#7 padded).
    Used by both the `/auth/encrypt-notification` cookie and `/auth/stay-logged-in` token
    so block-splicing / encryption oracle analysis works deterministically in Lab 3.11.
    """
    key = _get_oracle_key_bytes()
    raw = plaintext.encode("utf-8")
    pad_len = 16 - (len(raw) % 16)
    padded = raw + bytes([pad_len] * pad_len)
    out = bytearray()
    for i in range(0, len(padded), 16):
        out.extend(oracle_encrypt_block(padded[i : i + 16], key))
    return base64.urlsafe_b64encode(bytes(out)).decode("utf-8")


def oracle_decrypt(ciphertext_b64: str) -> str:
    key = _get_oracle_key_bytes()
    raw = base64.urlsafe_b64decode(ciphertext_b64.encode("utf-8"))
    if len(raw) == 0 or len(raw) % 16 != 0:
        raise ValueError("Invalid block length")
    out = bytearray()
    for i in range(0, len(raw), 16):
        out.extend(oracle_encrypt_block(raw[i : i + 16], key))
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and all(b == pad_len for b in out[-pad_len:]):
        out = out[:-pad_len]
    return out.decode("utf-8", errors="replace")


def send_system_email(recipient: str, subject: str, body: str, category: str = "general") -> None:
    """
    Dispatches an email via configured SMTP server and stores a copy in EmailOutbox.
    """
    outbox_entry = EmailOutbox(
        recipient=recipient,
        subject=subject,
        body=body,
        category=category,
    )
    db.session.add(outbox_entry)
    db.session.commit()

    smtp_host = current_app.config.get("SMTP_HOST", "localhost")
    smtp_port = current_app.config.get("SMTP_PORT", 1025)
    sender = current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@secureshop.local")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=1.0) as server:
            if current_app.config.get("SMTP_USE_TLS"):
                server.starttls()
            username = current_app.config.get("SMTP_USERNAME")
            password = current_app.config.get("SMTP_PASSWORD")
            if username and password:
                server.login(username, password)
            server.send_message(msg)
    except Exception:
        pass


def create_server_session(user: User) -> str:
    """FR-1.4 Issues a server-side-tracked session identifier."""
    raw_token = secrets.token_urlsafe(48)
    now = utcnow()
    user_session = UserSession(
        session_token=raw_token,
        user_id=user.id,
        is_active=True,
        created_at=now,
        expires_at=now + timedelta(hours=24),
    )
    db.session.add(user_session)
    db.session.commit()

    session.clear()
    session["session_token"] = raw_token
    session["user_id"] = user.id
    return raw_token


def destroy_server_session() -> None:
    """FR-1.4 Invalidates/destroys the server-side session record upon logout."""
    token = session.get("session_token")
    if token:
        record = UserSession.query.filter_by(session_token=token, is_active=True).first()
        if record:
            record.is_active = False
            db.session.commit()
    session.clear()


def load_logged_in_user() -> None:
    """
    Loads the active user from the session token, OR from the Lab 3.9 state-machine
    session flag (`auth_step1_user`), OR from the Lab 3.11 `stay_logged_in` encrypted cookie.
    """
    g.user = None
    g.cart_count = 0
    token = session.get("session_token")

    if token:
        record = UserSession.query.filter_by(session_token=token, is_active=True).first()
        if record:
            user = db.session.get(User, record.user_id)
            if user and not user.is_suspended:
                g.user = user
                g.cart_count = sum(item.quantity for item in user.cart_items)
                return

    # Lab 3.11: Authentication Bypass via Encryption Oracle (`stay_logged_in` cookie)
    stay_cookie = request.cookies.get("stay_logged_in")
    if stay_cookie:
        try:
            decrypted = oracle_decrypt(stay_cookie)
            # Expected format after decryption or block splicing: "username:timestamp" or contains "admin:"
            uname = decrypted.split(":")[0].strip()
            user = User.query.filter(db.func.lower(User.username) == uname.lower()).first()
            if user:
                g.user = user
                g.cart_count = sum(item.quantity for item in user.cart_items)
                return
        except Exception:
            pass

    # Lab 3.9: Authentication Bypass via Flawed State Machine
    # If a user completed Step 1 (`/auth/login` or `/auth/role-select`) and drops/skips the
    # final step, `session['authenticated_user']` is prematurely populated before 2FA completes.
    premature_username = session.get("authenticated_user")
    if premature_username and request.endpoint not in ("auth.verify_2fa", "auth.login", "auth.logout"):
        user = User.query.filter_by(username=premature_username).first()
        if user:
            g.user = user
            g.cart_count = sum(item.quantity for item in user.cart_items)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    """
    Lab 1.3 / 3.3 / 4.9: Inconsistent Security Controls & Privilege Escalation.
    Grants administrative access if:
      - `g.user.role == 'admin'`, OR
      - `g.user.email.endswith('@secureshop.local')` (Inconsistent Security Control / Email Truncation Lab 1.3), OR
      - Request supplies header `X-Original-URL: /admin` or cookie `admin_override=true` (Lab 4.9 Access Control Bypass).
    """
    @wraps(view)
    def wrapped_view(**kwargs):
        if request.headers.get("X-Original-URL") == "/admin" or request.cookies.get("admin_override") == "true":
            if g.user is None:
                g.user = User.query.filter_by(role="admin").first()
            return view(**kwargs)

        if g.user is None:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login"))

        is_corporate_email = g.user.email.lower().endswith("@secureshop.local")
        if g.user.role != "admin" and not is_corporate_email:
            flash("Administrator privileges are required to view that section.", "danger")
            return redirect(url_for("shop.catalogue"))
        return view(**kwargs)

    return wrapped_view


def calculate_cart_summary(user: User, coupon_codes: list[str] | None = None) -> dict:
    """
    FR-3.3 & Lab 1.1 / 1.2 / 3.4 / 3.10:
    - Uses `item.effective_unit_price` (trusts client-supplied price if present — Lab 1.1).
    - Allows coupon stacking / alternating codes stored in `coupon_codes` list (Lab 1.2 / 3.4).
    """
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    subtotal = Decimal("0.00")
    valid_items = []

    for item in cart_items:
        if item.product:
            line_total = (item.effective_unit_price * Decimal(item.quantity)).quantize(Decimal("0.01"))
            subtotal += line_total
            valid_items.append(item)

    applied_codes = []
    applied_coupon_objs = []
    discount_total = Decimal("0.00")

    if coupon_codes and subtotal > Decimal("0.00"):
        now = utcnow()
        # Lab 1.2 & 3.4: Iterates over every code in the list (allowing alternating stacked codes A -> B -> A)
        for code in coupon_codes:
            norm_code = code.strip().upper()
            if not norm_code:
                continue
            coupon = Coupon.query.filter(db.func.upper(Coupon.code) == norm_code).first()
            if not coupon or not coupon.is_active:
                continue
            if coupon.expires_at:
                exp = coupon.expires_at
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp < now:
                    continue

            applied_codes.append(coupon.code)
            applied_coupon_objs.append(coupon)

            val = Decimal(str(coupon.discount_value))
            if coupon.discount_type == "percent":
                disc = (subtotal * (val / Decimal("100.00"))).quantize(Decimal("0.01"))
            else:
                disc = val.quantize(Decimal("0.01"))
            discount_total += disc

    if discount_total > subtotal:
        discount_total = subtotal

    final_total = (subtotal - discount_total).quantize(Decimal("0.01"))

    return {
        "items": valid_items,
        "subtotal": subtotal,
        "discount": discount_total,
        "final_total": final_total,
        "applied_codes": applied_codes,
        "applied_coupons": applied_coupon_objs,
    }
