import json
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from secureshop.extensions import db
from secureshop.models import EmailOutbox, KeystrokeTelemetryLog, User
from secureshop.utils import (
    create_server_session,
    destroy_server_session,
    generate_totp_secret,
    get_totp_token,
    oracle_decrypt,
    oracle_encrypt,
    send_system_email,
    utcnow,
    verify_totp_code,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Lab 1.3 & 3.6: Legacy database/column boundary truncates stored email addresses at 32 characters
EMAIL_TRUNCATION_LIMIT = 32


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    FR-1.1 Account Registration & FR-1.2 Account Confirmation token generation.
    Includes Lab 1.3 / 3.3 / 3.6: Inconsistent Handling of Exceptional Input
    (Email Truncation at 32 chars after sending confirmation to full email, granting
    `@secureshop.local` admin privilege escalation).
    """
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        full_email = (request.form.get("email") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not username or not full_email or not password:
            flash("Username, email address, and password are required.", "danger")
            return render_template("auth/register.html")

        if "@" not in full_email:
            flash("Please provide a valid email address.", "danger")
            return render_template("auth/register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")

        # Lab 1.3 / 3.6: Silently truncate email at 32 characters when persisting to database!
        # e.g. a 32-char prefix ending in '@secureshop.local' followed by '.attacker.com'
        # sends the verification email to the full address, but saves the truncated
        # `@secureshop.local` address in the database!
        stored_email = full_email[:EMAIL_TRUNCATION_LIMIT]

        existing_user = User.query.filter(
            (db.func.lower(User.username) == username.lower())
            | (db.func.lower(User.email) == stored_email)
        ).first()
        if existing_user:
            flash("A user with that username or email address is already registered.", "danger")
            return render_template("auth/register.html")

        token = secrets.token_urlsafe(32)
        totp_secret = generate_totp_secret()
        initial_credit = Decimal(str(current_app.config.get("DEFAULT_INITIAL_STORE_CREDIT", "500.00")))

        # Lab 1.3 / 3.3: Automatically elevate role if truncated email ends with '@secureshop.local'
        assigned_role = "admin" if stored_email.endswith("@secureshop.local") else "customer"

        new_user = User(
            username=username,
            email=stored_email,
            display_name=display_name or username,
            role=assigned_role,
            store_credit=initial_credit,
            is_verified=False,
            verification_token=token,
            verification_sent_at=utcnow(),
            two_fa_enabled=True,
            totp_secret=totp_secret,
            passkey_credential_id=f"cred-{username}-01",
            passkey_public_key=f"pubkey-ed25519-{username}",
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        verify_url = url_for("auth.verify_email", token=token, _external=True)
        email_body = (
            f"Hello {new_user.display_name},\n\n"
            f"Thank you for registering at SecureShop!\n"
            f"Registered Email (Full): {full_email}\n"
            f"Database Stored Email (32-char column): {stored_email}\n"
            f"Assigned Account Role: {assigned_role}\n\n"
            f"Please confirm and activate your account by clicking the verification link below:\n\n"
            f"{verify_url}\n\n"
            f"Your Authenticator (TOTP) Secret Key: {totp_secret}"
        )
        # Email is dispatched to the FULL untampered address while the DB stores the truncated one
        send_system_email(
            recipient=full_email,
            subject="SecureShop - Confirm Your Account",
            body=email_body,
            category="verification",
        )

        flash(
            f"Registration successful! Confirmation sent to {full_email} "
            f"(stored as '{stored_email}'). View it in the Mail Outbox tab.",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/verify/<token>", methods=["GET"])
def verify_email(token: str):
    """FR-1.2 Verification token activation (also triggers Lab 1.3 role elevation on email change)."""
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        flash("Invalid or already used verification token.", "danger")
        return redirect(url_for("auth.login"))

    if user.pending_email:
        # Lab 1.3 / 3.6: Truncate pending email at 32 chars and elevate if @secureshop.local
        user.email = user.pending_email[:EMAIL_TRUNCATION_LIMIT]
        user.pending_email = None

    if user.email.lower().endswith("@secureshop.local"):
        user.role = "admin"

    user.is_verified = True
    user.verification_token = None
    user.verification_sent_at = None
    db.session.commit()

    flash(f"Account verified and activated (Email: {user.email}, Role: {user.role})! You may now sign in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email[:EMAIL_TRUNCATION_LIMIT]).first()
        if user and not user.is_verified:
            token = secrets.token_urlsafe(32)
            user.verification_token = token
            user.verification_sent_at = utcnow()
            db.session.commit()

            verify_url = url_for("auth.verify_email", token=token, _external=True)
            send_system_email(
                recipient=email,
                subject="SecureShop - New Account Confirmation Link",
                body=f"Hello {user.username},\n\nActivate your account using this link:\n{verify_url}",
                category="verification",
            )
        flash("If an unverified account matches that email, a new verification link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/resend_verification.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    FR-1.3 Standard & Multi-Factor Login + Lab 1.5, Lab 2.1-2.10, Lab 3.9, Lab 3.11, Lab 4.5, Lab 4.6:
    - Lab 1.5: Sets plaintext client cookie `verify=<username>` and generates a 4-digit OTP (0000-9999) with no rate limit.
    - Lab 2.1-2.5: Captures keystroke dynamics (`keystroke_intervals`, `raw_typed_keys`, `is_pasted`), stores raw keystrokes,
      and updates the user's behavioral baseline even on untrusted/anomalous logins (`learn_profile=1` — Behavioral Profile Poisoning).
    - Lab 2.8-2.10: Trusts client-supplied `region`, `gps_coords`, and `client_hour` parameters (Coordinate/GPS/Region/Off-Hours spoofing).
    - Lab 3.9: Prematurely stores `session['authenticated_user'] = user.username` after Step 1 so skipping `/auth/verify-2fa`
      bypasses the authentication state machine.
    - Lab 4.6: Supports `next` redirect parameter without domain validation (Redirect Attack Surface Exposure).
    """
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""
        next_url = (request.form.get("next") or request.args.get("next") or "").strip()

        # Behavioral & context telemetry fields (Lab 4 & Lab 5)
        intervals_raw = request.form.get("keystroke_intervals") or "[]"
        raw_typed_keys = request.form.get("raw_typed_keys") or password  # Lab 2.5 Sensitive Keystroke Data Exposure
        is_pasted = request.form.get("is_pasted") == "1"
        learn_profile = request.form.get("learn_profile", "1") == "1"
        client_region = (request.form.get("region") or request.headers.get("X-Region") or "US-EAST").strip()
        gps_coords = (request.form.get("gps_coords") or request.headers.get("X-GPS-Coords") or "40.7128,-74.0060").strip()
        client_hour_str = request.form.get("client_hour") or ""

        try:
            intervals = [float(x) for x in json.loads(intervals_raw) if isinstance(x, (int, float))]
        except Exception:
            intervals = []

        mean_interval = (sum(intervals) / len(intervals)) if intervals else (2.0 if is_pasted else 115.0)
        try:
            login_hour = int(client_hour_str) if client_hour_str else utcnow().hour
        except ValueError:
            login_hour = utcnow().hour

        # Classify behavioral & contextual threat signals (Lab 2.1 - 2.10)
        classification = "normal"
        if is_pasted or mean_interval < 15.0:
            classification = "automated_bot_or_credential_pasting"
        elif mean_interval > 280.0:
            classification = "imposter_unfamiliar_manual_typing"
        elif login_hour < 6 or login_hour > 22:
            classification = "off_hours_access"

        user = User.query.filter(
            (db.func.lower(User.username) == identifier.lower())
            | (db.func.lower(User.email) == identifier.lower())
        ).first()

        if user and client_region != (user.allowed_region or "US-EAST"):
            classification = f"remote_out_of_region_login ({client_region})"

        # Record telemetry log (Lab 2.5: exposes raw_typed_characters in DB and telemetry endpoint)
        telemetry = KeystrokeTelemetryLog(
            username=identifier or "anonymous",
            raw_typed_characters=raw_typed_keys,
            intervals_json=json.dumps(intervals),
            mean_interval_ms=round(mean_interval, 2),
            is_pasted=is_pasted,
            classification=classification,
            client_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            region=client_region,
            gps_coords=gps_coords,
            login_hour_utc=login_hour,
        )
        db.session.add(telemetry)
        db.session.commit()

        if not user or not user.check_password(password):
            # Lab 4.5 Data Leak: HTML comment in response body leaks whether username exists
            user_exists_hint = f"<!-- DEBUG_AUTH_HINT: user_found={bool(user)} identifier={identifier} -->"
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", debug_hint=user_exists_hint, next_url=next_url)

        if user.is_suspended:
            flash("This account has been suspended by an administrator.", "danger")
            return render_template("auth/login.html", next_url=next_url)

        if not user.is_verified:
            flash("Your email address is not verified yet. Please check the Mail Outbox.", "warning")
            return render_template("auth/login.html", next_url=next_url)

        # Lab 2.4: Behavioral Profile Poisoning (updates user's baseline mean from untrusted logins!)
        if learn_profile:
            old_mean = user.keystroke_profile_mean or 120.0
            user.keystroke_profile_mean = round((old_mean * 0.5) + (mean_interval * 0.5), 2)

        # Lab 1.5: 4-Digit OTP (0000 - 9999) for fast brute-force testing
        otp_code = f"{secrets.randbelow(10000):04d}"
        expiry_seconds = current_app.config.get("OTP_EXPIRY_SECONDS", 300)
        user.current_otp_code = otp_code
        user.otp_expires_at = utcnow() + timedelta(seconds=expiry_seconds)
        if not user.totp_secret:
            user.totp_secret = generate_totp_secret()
        db.session.commit()

        send_system_email(
            recipient=user.email,
            subject="SecureShop - Your 4-Digit 2FA Login Verification Code",
            body=(
                f"Hello {user.display_name or user.username},\n\n"
                f"Your 4-digit one-time verification code (OTP) for SecureShop login is: {otp_code}\n"
                f"Telemetry classification: {classification} (Mean interval: {mean_interval:.1f}ms, Region: {client_region}, GPS: {gps_coords})"
            ),
            category="2fa_otp",
        )

        session["pending_2fa_user_id"] = user.id
        # Lab 3.9: Flawed State Machine — prematurely sets `authenticated_user` before Step 2 completes!
        session["authenticated_user"] = user.username
        if next_url:
            session["post_login_redirect"] = next_url

        # Lab 4.6: Redirect Attack Surface Exposure (if `immediate_redirect=1` is passed, redirect immediately to `next_url`)
        if next_url and request.form.get("immediate_redirect") == "1":
            resp = make_response(redirect(next_url))
        else:
            resp = make_response(redirect(url_for("auth.verify_2fa", next=next_url)))

        # Lab 1.5: 2FA Broken Logic — client-side `verify` cookie controls whose account is logged in after 2FA!
        resp.set_cookie("verify", user.username, httponly=False, samesite="Lax")
        # Lab 4.5: Data Leak in response header for recon lab
        resp.headers["X-Debug-2FA-Target"] = user.username
        return resp

    next_url = request.args.get("next", "")
    return render_template("auth/login.html", next_url=next_url)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """
    FR-1.3 & Lab 1.5 / Lab 2.11 / Lab 4.6 / Lab 4.8:
    - Lab 1.5: Reads target account identity from the client-modifiable `verify` cookie (`request.cookies.get('verify')`)
      if present, allowing an attacker to pass their own 2FA or brute-force a 4-digit OTP with `verify=admin` or `verify=alice`!
    - Lab 1.5 & 4.8: No rate limiting or account lockout on OTP verification attempts.
    - Lab 2.11: OTP Code Capture / Replay — `user.current_otp_code` is NOT cleared after use unless `clear_otp=1`,
      allowing a captured OTP code to be replayed multiple times within its window!
    - Lab 4.6: Open redirect via `next` parameter upon 2FA completion.
    """
    # Lab 1.5: Trust the client-supplied `verify` cookie over the server session!
    verify_cookie_user = (request.cookies.get("verify") or "").strip()
    user = None
    if verify_cookie_user:
        user = User.query.filter(db.func.lower(User.username) == verify_cookie_user.lower()).first()

    if not user:
        pending_user_id = session.get("pending_2fa_user_id")
        if pending_user_id:
            user = db.session.get(User, pending_user_id)

    if not user:
        flash("Please sign in with your username and password first.", "warning")
        return redirect(url_for("auth.login"))

    next_url = (request.args.get("next") or request.form.get("next") or session.get("post_login_redirect") or "").strip()

    if request.method == "POST":
        code = (request.form.get("otp_code") or "").strip()
        if not code:
            flash("Please enter your verification code.", "danger")
            return render_template(
                "auth/verify_2fa.html",
                user=user,
                current_totp=get_totp_token(user.totp_secret),
                next_url=next_url,
            )

        # Check OTP against the cookie-specified user OR the pending session user (so swapping `verify=admin` with own OTP also works!)
        pending_user = db.session.get(User, session.get("pending_2fa_user_id")) if session.get("pending_2fa_user_id") else user

        otp_valid = False
        for candidate_user in (user, pending_user):
            if not candidate_user:
                continue
            if candidate_user.current_otp_code and candidate_user.current_otp_code == code:
                otp_valid = True
                break
            if verify_totp_code(candidate_user.totp_secret, code):
                otp_valid = True
                break

        if otp_valid:
            # Lab 2.11: OTP Code Capture / Replay — deliberately do NOT clear `current_otp_code` by default
            # so captured OTP codes can be replayed in Lab 2.11!
            if request.form.get("invalidate_otp") == "1":
                user.current_otp_code = None
                db.session.commit()

            session.pop("pending_2fa_user_id", None)
            session.pop("post_login_redirect", None)

            create_server_session(user)
            flash(f"2FA verified! Signed in as {user.display_name or user.username} ({user.role}).", "success")

            # Lab 4.6: Redirect Attack Surface Exposure (unvalidated redirect destination)
            if next_url:
                resp = make_response(redirect(next_url))
            else:
                resp = make_response(redirect(url_for("shop.catalogue")))

            # Lab 3.11: Issue encrypted `stay_logged_in` cookie using deterministic ECB oracle cipher
            resp.set_cookie("stay_logged_in", oracle_encrypt(f"{user.username}:{int(utcnow().timestamp())}"), httponly=False)
            return resp

        flash("Invalid 2FA verification code. Please try again.", "danger")

    return render_template(
        "auth/verify_2fa.html",
        user=user,
        current_totp=get_totp_token(user.totp_secret),
        next_url=next_url,
    )


@auth_bp.route("/passkey/verify", methods=["POST"])
def verify_passkey():
    """
    Lab 5 (2.12): Cryptographic Signature Tampering (Flipped Byte) & Credential ID Mismatch.
    Accepts JSON or form payload:
      - `username`: target username
      - `credential_id`: WebAuthn credential ID
      - `signature`: hex or base64 signature string
      - `challenge`: challenge string
    Intentionally exhibits two exploitable flaws when `strict_verify` is not enabled:
      1. Does not verify that `credential_id` belongs to `username` (Credential ID Mismatch).
      2. Only compares the first 4 characters of `signature` against the expected HMAC/Ed25519 stub,
         allowing a flipped byte in the remainder of the signature to pass verification!
    """
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    credential_id = (data.get("credential_id") or "").strip()
    signature = (data.get("signature") or "").strip()

    user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Check if ANY user owns `credential_id` (Credential ID Mismatch vulnerability: doesn't check `owner.id == user.id`)
    cred_owner = User.query.filter_by(passkey_credential_id=credential_id).first()
    if not cred_owner and not credential_id.startswith("cred-"):
        return jsonify({"status": "error", "message": "Unknown credential_id"}), 400

    # Weak signature verification: accepts any signature starting with "sig_" or matching first 4 chars (Flipped Byte vulnerability)
    if len(signature) < 4 or not (signature.startswith("sig_") or signature[:4] == "a1b2"):
        return jsonify({"status": "error", "message": "Invalid signature header"}), 401

    create_server_session(user)
    return jsonify({
        "status": "authenticated",
        "authenticated_as": user.username,
        "role": user.role,
        "credential_id_used": credential_id,
        "signature_accepted": signature,
        "vulnerability_note": "Accepted passkey without binding credential_id to user and ignored flipped trailing signature bytes.",
    }), 200


@auth_bp.route("/phishing-capture", methods=["POST", "GET"])
def phishing_capture():
    """
    Lab 2.7: Password Phishing & Credential Harvesting simulation endpoint within the local lab.
    Records captured credentials or renders a simulated lookalike login prompt for Red/Blue team exercises.
    """
    if request.method == "POST":
        captured_user = request.form.get("username") or request.form.get("identifier") or ""
        captured_pass = request.form.get("password") or ""
        captured_otp = request.form.get("otp") or ""
        send_system_email(
            recipient="soc-alerts@secureshop.local",
            subject=f"[Lab 2.7 Phishing Simulation] Captured credentials for {captured_user}",
            body=f"Username: {captured_user}\nPassword: {captured_pass}\nOTP: {captured_otp}",
            category="phishing_sim",
        )
        return jsonify({
            "status": "captured",
            "username": captured_user,
            "password_leaked": captured_pass,
            "otp_leaked": captured_otp,
        }), 200

    return jsonify({
        "endpoint": "/auth/phishing-capture",
        "description": "POST username, password, and optional otp to simulate Lab 2.7 credential phishing capture.",
    }), 200


@auth_bp.route("/encrypt-notification", methods=["POST", "GET"])
def encrypt_notification():
    """
    Lab 3.11: Authentication Bypass via Encryption Oracle.
    Encrypts arbitrary user-supplied `message` parameter using the exact same deterministic
    16-byte ECB key and cipher used by the `stay_logged_in` authentication cookie, and also
    decrypts any `cipher` parameter as a decryption/encryption oracle!
    """
    msg = request.values.get("message") or ""
    cipher_in = request.values.get("cipher") or request.cookies.get("notification") or ""

    encrypted_out = oracle_encrypt(msg) if msg else ""
    decrypted_out = ""
    if cipher_in:
        try:
            decrypted_out = oracle_decrypt(cipher_in)
        except Exception as exc:
            decrypted_out = f"error: {exc}"

    resp = make_response(jsonify({
        "input_message": msg,
        "oracle_ciphertext": encrypted_out,
        "decrypted_notification": decrypted_out,
        "hint": "16-byte ECB block oracle shared with stay_logged_in cookie (format: username:timestamp)",
    }))
    if encrypted_out:
        resp.set_cookie("notification", encrypted_out, httponly=False)
    return resp


@auth_bp.route("/telemetry-logs", methods=["GET"])
def telemetry_logs():
    """
    Lab 2.5 & Lab 4.5: Sensitive Keystroke Data Exposure & Data Leaks.
    Exposes raw keystroke telemetry, plaintext passwords typed, intervals, IP, region, and GPS coordinates
    without authentication!
    """
    logs = KeystrokeTelemetryLog.query.order_by(KeystrokeTelemetryLog.id.desc()).limit(50).all()
    users = User.query.all()
    return jsonify({
        "telemetry_count": len(logs),
        "keystroke_logs": [
            {
                "id": l.id,
                "username": l.username,
                "raw_typed_characters": l.raw_typed_characters,
                "intervals_ms": json.loads(l.intervals_json or "[]"),
                "mean_interval_ms": l.mean_interval_ms,
                "is_pasted": l.is_pasted,
                "classification": l.classification,
                "region": l.region,
                "gps_coords": l.gps_coords,
                "login_hour_utc": l.login_hour_utc,
            }
            for l in logs
        ],
        "user_Credentials_dump": [
            {
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "plaintext_password": u.plaintext_password,
                "totp_secret": u.totp_secret,
                "current_otp_code": u.current_otp_code,
                "keystroke_profile_mean": u.keystroke_profile_mean,
                "passkey_credential_id": u.passkey_credential_id,
            }
            for u in users
        ],
    }), 200


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    """FR-1.4 Invalidates and destroys the session upon logout."""
    destroy_server_session()
    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie("verify")
    resp.delete_cookie("stay_logged_in")
    flash("You have been signed out and your session has been destroyed.", "info")
    return resp


@auth_bp.route("/outbox", methods=["GET"])
def mail_outbox():
    """Offline Demo Mail Outbox viewer for testing FR-1.2 email confirmation links & FR-1.3 2FA OTPs."""
    emails = EmailOutbox.query.order_by(EmailOutbox.created_at.desc()).limit(30).all()
    return render_template("auth/outbox.html", emails=emails)
