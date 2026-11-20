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
from flask import current_app, flash, g, redirect, session, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Coupon, CouponUsage, EmailOutbox, User, UserSession


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


def send_system_email(recipient: str, subject: str, body: str, category: str = "general") -> None:
    """
    Dispatches an email via configured SMTP server (e.g. MailHog/Mailpit) and always stores
    a copy in the database EmailOutbox for instant offline verification and testing.
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
        with smtplib.SMTP(smtp_host, smtp_port, timeout=1.5) as server:
            if current_app.config.get("SMTP_USE_TLS"):
                server.starttls()
            username = current_app.config.get("SMTP_USERNAME")
            password = current_app.config.get("SMTP_PASSWORD")
            if username and password:
                server.login(username, password)
            server.send_message(msg)
    except Exception:
        # Fallback to EmailOutbox already committed above
        pass


def create_server_session(user: User) -> str:
    """FR-1.4 Issues a cryptographically signed, server-side-tracked session identifier."""
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
    """Loads the active user from the server-side tracked session token."""
    g.user = None
    g.cart_count = 0
    token = session.get("session_token")
    if not token:
        return

    record = UserSession.query.filter_by(session_token=token, is_active=True).first()
    if not record:
        session.clear()
        return

    now = utcnow()
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        record.is_active = False
        db.session.commit()
        session.clear()
        return

    user = db.session.get(User, record.user_id)
    if not user or user.is_suspended:
        record.is_active = False
        db.session.commit()
        session.clear()
        return

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
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if g.user.role != "admin":
            flash("Administrator privileges are required to view that section.", "danger")
            return redirect(url_for("shop.catalogue"))
        return view(**kwargs)

    return wrapped_view


def calculate_cart_summary(user: User, coupon_codes: list[str] | None = None) -> dict:
    """
    FR-3.3 & FR-4.2: Dynamically calculates line-item totals, subtotal, coupon discounts,
    and final order total based on authoritative server-side product pricing.
    """
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    subtotal = Decimal("0.00")
    valid_items = []

    for item in cart_items:
        if item.product:
            line_total = (Decimal(str(item.product.price)) * Decimal(item.quantity)).quantize(Decimal("0.01"))
            subtotal += line_total
            valid_items.append(item)

    applied_codes = []
    applied_coupon_objs = []
    discount_total = Decimal("0.00")

    if coupon_codes and subtotal > Decimal("0.00"):
        seen_codes = set()
        now = utcnow()
        for code in coupon_codes:
            norm_code = code.strip().upper()
            if not norm_code or norm_code in seen_codes:
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
            if coupon.total_usage_limit is not None and coupon.times_used >= coupon.total_usage_limit:
                continue
            user_uses = CouponUsage.query.filter_by(coupon_id=coupon.id, user_id=user.id).count()
            if user_uses >= coupon.max_uses_per_user:
                continue

            seen_codes.add(norm_code)
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
