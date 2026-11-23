import base64
import hashlib
import hmac
import ipaddress
import math
import re
import secrets
import smtplib
import struct
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import abort, current_app, flash, g, redirect, request, session, url_for

from secureshop.extensions import db
from secureshop.models import (
    CartItem,
    Coupon,
    CouponUsage,
    EmailOutbox,
    SecurityAuditLog,
    User,
    UserSession,
)

# Strict RFC-5322 compatible email regex & username regex (SR-3)
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")

# In-memory sliding-window rate limiter per (ip, bucket)
_RATE_LIMIT_STORE: dict[tuple[str, str], list[float]] = defaultdict(list)


def utcnow():
    return datetime.now(timezone.utc)


def get_client_ip() -> str:
    """Returns authoritative socket remote_addr (never trusts spoofable X-Forwarded-For)."""
    return request.remote_addr or "127.0.0.1"


def log_security_event(event_type: str, details: str, severity: str = "INFO", username: str | None = None) -> None:
    """Records a security audit log entry without ever storing passwords or raw keystrokes."""
    try:
        entry = SecurityAuditLog(
            event_type=event_type,
            severity=severity,
            username=username,
            ip_address=get_client_ip(),
            details=details[:500],
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ==============================================================================
# SR-3: Strict Input Validation & Safe Redirects (Lab 1.3 / 3.6 / 4.6 / 4.7)
# ==============================================================================
def validate_email_strict(email: str) -> tuple[bool, str]:
    """
    Validates email length (<= 254 chars, local part <= 64 chars) and format strictly
    BEFORE any email dispatch or database persistence. Rejects over-long inputs with 400.
    """
    if not email:
        return False, "Email address is required."
    if len(email) > 254:
        return False, "Email address exceeds maximum RFC length of 254 characters."
    if any(ch in email for ch in ("\r", "\n", "\x00")):
        return False, "Email address contains forbidden control characters."
    parts = email.split("@")
    if len(parts) != 2 or len(parts[0]) > 64 or len(parts[0]) == 0:
        return False, "Invalid email address format."
    if not EMAIL_REGEX.match(email):
        return False, "Please provide a valid email address."
    return True, ""


def validate_username_strict(username: str) -> tuple[bool, str]:
    if not username or not USERNAME_REGEX.match(username):
        return False, "Username must be 3-64 characters (letters, digits, _, ., -)."
    return True, ""


def is_safe_redirect_url(target: str | None) -> bool:
    """
    Lab 4.6 Redirect Attack Surface Protection:
    Only allows relative internal paths starting with a single `/` and no scheme/netloc.
    Blocks `https://evil.com`, `//evil.com`, `\\evil.com`, and `javascript:` URLs.
    """
    if not target:
        return False
    cleaned = target.strip()
    if not cleaned.startswith("/") or cleaned.startswith("//") or cleaned.startswith("/\\"):
        return False
    parsed = urlparse(cleaned)
    return parsed.scheme == "" and parsed.netloc == ""


def safe_redirect_target(target: str | None, fallback_endpoint: str = "shop.catalogue") -> str:
    if is_safe_redirect_url(target):
        return target.strip()
    return url_for(fallback_endpoint)


def safe_resolve_path(base_dir: Path, requested_filename: str) -> Path | None:
    """
    Lab 4.4 Directory Traversal Protection:
    Canonicalizes path and strictly verifies it remains inside `base_dir`.
    """
    if not requested_filename or "/" in requested_filename or "\\" in requested_filename or ".." in requested_filename:
        return None
    base_resolved = base_dir.resolve()
    candidate = (base_resolved / requested_filename).resolve()
    if candidate.parent != base_resolved:
        return None
    return candidate


# ==============================================================================
# SR-8: Anti-CSRF Token Generation & Enforcement
# ==============================================================================
def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token() -> bool:
    expected = session.get("_csrf_token")
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not submitted:
        return False
    return hmac.compare_digest(str(expected), str(submitted))


# ==============================================================================
# SR-6 / Lab 4.8: Rate Limiting & Brute-Force Protection
# ==============================================================================
def check_rate_limit(bucket: str, max_requests: int, window_seconds: int = 60) -> bool:
    """Returns True if request is allowed, False if rate limit is exceeded."""
    key = (get_client_ip(), bucket)
    now = time.monotonic()
    cutoff = now - window_seconds
    timestamps = [ts for ts in _RATE_LIMIT_STORE[key] if ts > cutoff]
    if len(timestamps) >= max_requests:
        _RATE_LIMIT_STORE[key] = timestamps
        return False
    timestamps.append(now)
    _RATE_LIMIT_STORE[key] = timestamps
    return True


def reset_rate_limits() -> None:
    """Helper for isolated test suites."""
    _RATE_LIMIT_STORE.clear()


# ==============================================================================
# Lab 4 (2.2 - 2.5): Behavioral Keystroke Analysis & Privacy-Preserving Baseline
# ==============================================================================
def analyze_keystroke_intervals(intervals_raw: str | list | None, is_pasted: bool, user: User | None) -> dict:
    """
    Analyzes ONLY numeric inter-key timing intervals (milliseconds).
    Never accepts or stores raw typed characters (defends against Lab 2.5 Sensitive Keystroke Data Exposure).
    Detects:
      - Lab 2.2: Automated Bot / Credential Pasting (`is_pasted` or mean < 20ms or zero variance)
      - Lab 2.3: Imposter / Unfamiliar Manual Typing (> 2.5 std deviations from trusted user baseline)
    """
    if is_pasted:
        return {"trusted": False, "anomaly": "automated_bot_or_paste", "mean_ms": 0.0, "std_ms": 0.0}

    intervals: list[float] = []
    if isinstance(intervals_raw, list):
        raw_list = intervals_raw
    elif isinstance(intervals_raw, str) and intervals_raw.strip():
        try:
            import json
            parsed = json.loads(intervals_raw)
            raw_list = parsed if isinstance(parsed, list) else []
        except Exception:
            raw_list = []
    else:
        raw_list = []

    for val in raw_list[:100]:
        if isinstance(val, (int, float)) and 0 <= val <= 5000:
            intervals.append(float(val))

    if not intervals:
        # No telemetry supplied (e.g., standard non-JS client): treat as neutral/normal without poisoning baseline
        return {"trusted": True, "anomaly": None, "mean_ms": None, "std_ms": None}

    mean_ms = sum(intervals) / len(intervals)
    variance = sum((x - mean_ms) ** 2 for x in intervals) / len(intervals)
    std_ms = math.sqrt(variance)

    # Lab 2.2 Automated Bot / Credential Pasting detection
    if mean_ms < 20.0 or (len(intervals) >= 5 and std_ms < 2.0):
        return {"trusted": False, "anomaly": "automated_bot_or_paste", "mean_ms": mean_ms, "std_ms": std_ms}

    # Lab 2.3 Imposter / Unfamiliar Manual Typing detection against trusted baseline
    if user and user.keystroke_sample_count >= 3 and user.keystroke_mean_ms is not None:
        baseline_std = max(user.keystroke_std_ms or 35.0, 35.0)
        z_score = abs(mean_ms - user.keystroke_mean_ms) / baseline_std
        if z_score > 3.0:
            return {"trusted": False, "anomaly": "imposter_typing_pattern", "mean_ms": mean_ms, "std_ms": std_ms}

    return {"trusted": True, "anomaly": None, "mean_ms": mean_ms, "std_ms": std_ms}


def update_trusted_keystroke_profile(user: User, mean_ms: float | None, std_ms: float | None) -> None:
    """
    Lab 2.4 Behavioral Profile Poisoning Defense:
    Called ONLY after full MFA (Password + 2FA/Passkey) succeeds AND no behavioral anomaly was detected.
    Uses bounded exponential moving average so a single session cannot poison the baseline.
    """
    if mean_ms is None or std_ms is None:
        return
    if user.keystroke_sample_count == 0 or user.keystroke_mean_ms is None:
        user.keystroke_mean_ms = round(mean_ms, 2)
        user.keystroke_std_ms = round(max(std_ms, 25.0), 2)
    else:
        alpha = 0.2
        user.keystroke_mean_ms = round((1 - alpha) * user.keystroke_mean_ms + alpha * mean_ms, 2)
        user.keystroke_std_ms = round((1 - alpha) * (user.keystroke_std_ms or 25.0) + alpha * max(std_ms, 25.0), 2)
    user.keystroke_sample_count += 1


# ==============================================================================
# Lab 5 (2.8 - 2.10): Server-Side IP Geolocation & Off-Hours Access Defense
# ==============================================================================
def resolve_server_side_region(ip_str: str) -> str:
    """
    Lab 2.8 & 2.10 Defense: Derives region strictly from server-side socket IP,
    ignoring client-spoofable GPS coordinates (`gps_coords`) or `X-Region` headers.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_private:
            return "LOCAL"
    except ValueError:
        return "UNKNOWN"
    # Deterministic simulated GeoIP mapping for public test IPs
    first_octet = int(ip_str.split(".")[0]) if "." in ip_str else 0
    if first_octet in range(1, 100):
        return "US-EAST"
    if first_octet in range(100, 170):
        return "EU-WEST"
    return "FOREIGN-UNTRUSTED"


def check_context_access_policy(user: User) -> tuple[bool, str, str]:
    """
    Evaluates:
      - Lab 2.8 Remote / Out-of-Region Login (using server-derived IP region)
      - Lab 2.9 Off-Hours Access (using server UTC clock, never client clock)
      - Lab 2.10 Coordinate / GPS Spoofing (explicitly ignores client GPS coords)
    Returns (allowed, server_region, reason).
    """
    server_region = resolve_server_side_region(get_client_ip())
    allowed_regions = current_app.config.get("ALLOWED_REGIONS", ["LOCAL", "US-EAST", "US-WEST", "EU-WEST"])

    if server_region not in allowed_regions:
        return False, server_region, f"Login blocked: out-of-region IP detected ({server_region})."

    if current_app.config.get("ENFORCE_BUSINESS_HOURS", False):
        hour = utcnow().hour
        start_h = current_app.config.get("ALLOWED_LOGIN_HOUR_START", 6)
        end_h = current_app.config.get("ALLOWED_LOGIN_HOUR_END", 22)
        if not (start_h <= hour <= end_h):
            return False, server_region, f"Login blocked: off-hours access attempt at {hour:02d}:00 UTC."

    return True, server_region, ""


# ==============================================================================
# Lab 5 (2.12): Cryptographic Ed25519 Passkey / WebAuthn Signature Verification
# ==============================================================================
def verify_ed25519_passkey_signature(public_key_pem: str, challenge: str, signature_b64: str) -> bool:
    """
    Verifies full Ed25519 cryptographic signature over the server-issued single-use challenge.
    Any flipped byte or tampered signature immediately fails verification.
    """
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(pub_key, Ed25519PublicKey):
            return False
        sig_bytes = base64.urlsafe_b64decode(signature_b64.encode("utf-8"))
        pub_key.verify(sig_bytes, challenge.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ==============================================================================
# FR-1.3 & Lab 2.11: 6-Digit OTP Hashing & Replay-Protected TOTP
# ==============================================================================
def hash_otp_code(code: str) -> str:
    secret = current_app.config.get("SECRET_KEY", "secureshop").encode("utf-8")
    return hmac.new(secret, code.strip().encode("utf-8"), hashlib.sha256).hexdigest()


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


def verify_totp_code_no_replay(user: User, candidate: str) -> bool:
    """
    Lab 2.11 OTP Code Capture / Replay Defense:
    Verifies a 6-digit TOTP code and enforces strictly monotonic time-step tracking
    (`step > user.last_used_totp_step`) so a captured TOTP code can NEVER be replayed.
    """
    if not user.totp_secret or not candidate:
        return False
    candidate = candidate.strip()
    current_step = int(time.time() // 30)
    last_step = user.last_used_totp_step or 0

    for offset in (-1, 0, 1):
        step = current_step + offset
        if step <= last_step:
            continue
        if hmac.compare_digest(get_totp_token(user.totp_secret, offset), candidate):
            user.last_used_totp_step = step
            return True
    return False


def send_system_email(recipient: str, subject: str, body: str, category: str = "general") -> None:
    """
    Dispatches an email via configured SMTP server (e.g. MailHog/Mailpit) and stores
    a copy in the database EmailOutbox for offline verification.
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


# ==============================================================================
# FR-1.4 & SR-6 / Lab 3.9: Hardened Server-Side Session Lifecycle
# ==============================================================================
def create_server_session(user: User) -> str:
    """
    Issues a cryptographically random, server-side-tracked session identifier AFTER
    complete MFA verification (regenerates session & CSRF token to prevent fixation).
    """
    raw_token = secrets.token_urlsafe(48)
    now = utcnow()
    lifetime = current_app.config.get("PERMANENT_SESSION_LIFETIME", 28800)
    if isinstance(lifetime, timedelta):
        expires_at = now + lifetime
    else:
        expires_at = now + timedelta(seconds=int(lifetime))
    ua_hash = hashlib.sha256((request.headers.get("User-Agent") or "").encode("utf-8")).hexdigest()

    user_session = UserSession(
        session_token=raw_token,
        user_id=user.id,
        ip_address=get_client_ip(),
        user_agent_hash=ua_hash,
        is_active=True,
        created_at=now,
        expires_at=expires_at,
    )
    db.session.add(user_session)
    db.session.commit()

    session.clear()
    session.permanent = True
    session["session_token"] = raw_token
    session["auth_state"] = "AUTHENTICATED"
    session["_csrf_token"] = secrets.token_urlsafe(32)
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


def revoke_all_user_sessions(user_id: int) -> None:
    """Revokes all active sessions for a user (used on password change or suspension)."""
    UserSession.query.filter_by(user_id=user_id, is_active=True).update({"is_active": False})
    db.session.commit()


def load_logged_in_user() -> None:
    """
    Loads the active user strictly from the server-side tracked session token.
    Never trusts client cookies like `verify`, `stay_logged_in`, or partial MFA states (SR-6 / Lab 3.9).
    """
    g.user = None
    g.cart_count = 0

    if session.get("auth_state") != "AUTHENTICATED":
        return

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
    if not user or user.is_suspended or not user.is_verified:
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
    """
    SR-4 Explicit Role-Based Access Control (RBAC):
    Enforces `g.user.role == 'admin'` strictly server-side from database state.
    Never trusts email domain substrings, headers (`X-Original-URL`), or cookies (`admin_override`).
    """
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if g.user.role != "admin":
            log_security_event(
                "RBAC_VIOLATION",
                f"Unauthorized admin access attempt to {request.path} by role={g.user.role}",
                severity="HIGH",
                username=g.user.username,
            )
            abort(403)
        return view(**kwargs)

    return wrapped_view


# ==============================================================================
# SR-1 & SR-2: Authoritative Server-Side Pricing & Strict Coupon Business Rules
# ==============================================================================
def calculate_cart_summary(user: User, coupon_codes: list[str] | None = None) -> dict:
    """
    SR-1 & SR-2:
    - Computes line-item totals and subtotal strictly from authoritative `Product.price`.
    - Deduplicates coupons using a case-insensitive set (blocks alternating replay `A -> B -> A`).
    - Enforces `MAX_COUPONS_PER_ORDER` and `MAX_CUMULATIVE_DISCOUNT_PERCENT` hard cap (prevents $0/negative totals).
    """
    cart_items = CartItem.query.filter_by(user_id=user.id).all()
    subtotal = Decimal("0.00")
    valid_items = []

    for item in cart_items:
        if item.product and item.quantity > 0:
            unit_price = Decimal(str(item.product.price)).quantize(Decimal("0.01"))
            if unit_price < Decimal("0.00"):
                continue
            line_total = (unit_price * Decimal(item.quantity)).quantize(Decimal("0.01"))
            subtotal += line_total
            valid_items.append(item)

    applied_codes = []
    applied_coupon_objs = []
    discount_total = Decimal("0.00")

    max_coupons = current_app.config.get("MAX_COUPONS_PER_ORDER", 2)
    max_discount_pct = Decimal(str(current_app.config.get("MAX_CUMULATIVE_DISCOUNT_PERCENT", 50)))

    if coupon_codes and subtotal > Decimal("0.00"):
        seen_codes: set[str] = set()
        now = utcnow()
        for code in coupon_codes:
            if len(applied_codes) >= max_coupons:
                break
            norm_code = (code or "").strip().upper()
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

    # Hard cap on maximum cumulative discount (SR-2: prevents excessive stacking & negative totals)
    max_allowed_discount = (subtotal * (max_discount_pct / Decimal("100.00"))).quantize(Decimal("0.01"))
    if discount_total > max_allowed_discount:
        discount_total = max_allowed_discount
    if discount_total < Decimal("0.00"):
        discount_total = Decimal("0.00")

    final_total = (subtotal - discount_total).quantize(Decimal("0.01"))
    if final_total < Decimal("0.00"):
        final_total = Decimal("0.00")

    return {
        "items": valid_items,
        "subtotal": subtotal,
        "discount": discount_total,
        "final_total": final_total,
        "applied_codes": applied_codes,
        "applied_coupons": applied_coupon_objs,
    }
