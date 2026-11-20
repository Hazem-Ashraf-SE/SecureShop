import secrets
from datetime import timedelta, timezone
from decimal import Decimal
from flask import Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
from secureshop.extensions import db
from secureshop.models import EmailOutbox, User, WebAuthnCredential
from secureshop.utils import (
    analyze_keystroke_intervals,
    check_context_access_policy,
    check_rate_limit,
    create_server_session,
    destroy_server_session,
    generate_totp_secret,
    get_totp_token,
    hash_otp_code,
    log_security_event,
    safe_redirect_target,
    send_system_email,
    update_trusted_keystroke_profile,
    utcnow,
    validate_email_strict,
    validate_username_strict,
    verify_ed25519_passkey_signature,
    verify_totp_code_no_replay,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    FR-1.1, FR-1.2 & SR-3:
    - Validates username and email strictly at the controller boundary BEFORE any DB write or email dispatch.
    - Rejects over-long emails (> 254 chars) with HTTP 400 Bad Request (no silent truncation).
    - Always assigns `role='customer'` regardless of email domain or client parameters (SR-4).
    - Hashes passwords with bcrypt (SR-7 / Lab 2.6).
    """
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if request.method == "POST":
        if not check_rate_limit("register", max_requests=10, window_seconds=300):
            log_security_event("RATE_LIMIT_REGISTER", "Registration rate limit exceeded", severity="WARNING")
            return render_template("auth/register.html"), 429

        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        # SR-3: Strict length & format validation BEFORE email dispatch or DB persistence -> 400 Bad Request
        valid_u, err_u = validate_username_strict(username)
        if not valid_u:
            flash(err_u, "danger")
            return render_template("auth/register.html"), 400

        valid_e, err_e = validate_email_strict(email)
        if not valid_e:
            log_security_event("INPUT_VALIDATION_REJECTED", f"Invalid email rejected: len={len(email)}", severity="WARNING")
            flash(err_e, "danger")
            return render_template("auth/register.html"), 400

        if len(display_name) > 100:
            flash("Display name must be 100 characters or fewer.", "danger")
            return render_template("auth/register.html"), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html"), 400

        if len(password) < 8 or len(password) > 128:
            flash("Password must be between 8 and 128 characters long.", "danger")
            return render_template("auth/register.html"), 400

        existing_user = User.query.filter(
            (db.func.lower(User.username) == username.lower()) | (db.func.lower(User.email) == email)
        ).first()
        if existing_user:
            flash("An account with that username or email address cannot be created.", "danger")
            return render_template("auth/register.html"), 400

        token = secrets.token_urlsafe(32)
        totp_secret = generate_totp_secret()
        initial_credit = Decimal(str(current_app.config.get("DEFAULT_INITIAL_STORE_CREDIT", "500.00")))

        # SR-4: Role is ALWAYS explicitly hardcoded to 'customer' on registration
        new_user = User(
            username=username,
            email=email,
            display_name=display_name or username,
            role="customer",
            store_credit=initial_credit,
            is_verified=False,
            verification_token=token,
            verification_sent_at=utcnow(),
            two_fa_enabled=True,
            totp_secret=totp_secret,
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        verify_url = url_for("auth.verify_email", token=token, _external=True)
        email_body = (
            f"Hello {new_user.display_name},\n\n"
            f"Thank you for registering at SecureShop!\n"
            f"Please confirm and activate your account by clicking the single-use verification link below:\n\n"
            f"{verify_url}\n\n"
            f"Your Authenticator (TOTP) Secret Key: {totp_secret}\n"
            f"This verification link expires in 1 hour."
        )
        send_system_email(
            recipient=new_user.email,
            subject="SecureShop - Confirm Your Account",
            body=email_body,
            category="verification",
        )

        log_security_event("USER_REGISTERED", "New customer account registered (pending verification)", username=username)
        flash(
            "Registration successful! A single-use confirmation link has been sent to your email "
            "(viewable in the Demo Mail Outbox tab).",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/verify/<token>", methods=["GET"])
def verify_email(token: str):
    """FR-1.2 Single-use, time-bound verification token activation."""
    if not token or len(token) > 128:
        flash("Invalid verification token.", "danger")
        return redirect(url_for("auth.login")), 400

    user = User.query.filter_by(verification_token=token).first()
    if not user:
        flash("Invalid or already used verification token.", "danger")
        return redirect(url_for("auth.login"))

    max_age = current_app.config.get("VERIFICATION_TOKEN_MAX_AGE", 3600)
    sent_at = user.verification_sent_at
    if sent_at:
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        if (utcnow() - sent_at).total_seconds() > max_age:
            user.verification_token = None
            user.verification_sent_at = None
            db.session.commit()
            flash("Verification link has expired. Please request a new confirmation email.", "danger")
            return redirect(url_for("auth.resend_verification"))

    if user.pending_email:
        valid_e, _ = validate_email_strict(user.pending_email)
        if valid_e:
            user.email = user.pending_email
        user.pending_email = None

    user.is_verified = True
    user.verification_token = None  # Single-use token invalidated immediately
    user.verification_sent_at = None
    db.session.commit()

    log_security_event("EMAIL_VERIFIED", "Account email verified via single-use token", username=user.username)
    flash("Your account has been verified and activated! You may now sign in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    """Allows unverified users to request a fresh single-use verification link."""
    if request.method == "POST":
        if not check_rate_limit("resend_verify", max_requests=5, window_seconds=300):
            flash("Too many verification requests. Please wait a few minutes.", "danger")
            return render_template("auth/resend_verification.html"), 429

        email = (request.form.get("email") or "").strip().lower()
        valid_e, _ = validate_email_strict(email)
        if valid_e:
            user = User.query.filter(db.func.lower(User.email) == email).first()
            if user and not user.is_verified:
                token = secrets.token_urlsafe(32)
                user.verification_token = token
                user.verification_sent_at = utcnow()
                db.session.commit()

                verify_url = url_for("auth.verify_email", token=token, _external=True)
                send_system_email(
                    recipient=user.email,
                    subject="SecureShop - New Account Confirmation Link",
                    body=f"Hello {user.username},\n\nActivate your account using this single-use link:\n{verify_url}",
                    category="verification",
                )
        flash("If an unverified account matches that email, a new verification link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/resend_verification.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    FR-1.3, SR-6, Lab 2.1-2.10, Lab 3.9, Lab 4.6, Lab 4.8:
    - Rate limiting & account lockout on failed attempts (blocks brute-force / fuzzing).
    - Behavioral keystroke timing analysis (numeric intervals ONLY; raw keys are NEVER accepted or stored).
    - Server-side IP geolocation & UTC clock checks (blocks out-of-region, off-hours, and ignores GPS spoofing).
    - Cryptographic 6-digit OTP stored hashed (`current_otp_hash`) and bound to server-side `session['pending_2fa_user_id']`.
    - Strict state machine: `session['auth_state'] = 'PENDING_2FA'` (never grants authenticated access until Step 2 completes).
    - Safe relative-only redirect validation for `next` parameter (blocks open redirect / phishing chains).
    """
    if g.user:
        return redirect(url_for("shop.catalogue"))

    next_url = request.args.get("next", "")

    if request.method == "POST":
        if not check_rate_limit("login", max_requests=20, window_seconds=60):
            log_security_event("BRUTE_FORCE_BLOCKED", "IP login rate limit exceeded", severity="HIGH")
            flash("Too many login attempts from your network. Please wait before trying again.", "danger")
            return render_template("auth/login.html", next_url=next_url), 429

        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.form.get("next") or next_url

        # Lab 2.5: Only accept numeric inter-keystroke intervals; ignore/discard any raw keystroke text
        intervals_raw = request.form.get("keystroke_intervals")
        is_pasted = request.form.get("is_pasted") == "1"

        if not identifier or not password or len(identifier) > 254 or len(password) > 128:
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", next_url=next_url), 400

        user = User.query.filter(
            (db.func.lower(User.username) == identifier.lower())
            | (db.func.lower(User.email) == identifier.lower())
        ).first()

        now = utcnow()
        # Check per-account lockout (SR-6 / Lab 4.8)
        if user and user.login_locked_until:
            locked_until = user.login_locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if now < locked_until:
                log_security_event("LOCKED_LOGIN_ATTEMPT", "Attempt on locked account", severity="WARNING", username=user.username)
                flash("Account temporarily locked due to too many failed attempts. Please try again later.", "danger")
                return render_template("auth/login.html", next_url=next_url), 429

        # Constant-behavior check: generic error message prevents username enumeration (Lab 4.5)
        if not user or not user.check_password(password):
            if user:
                user.failed_login_attempts += 1
                max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)
                if user.failed_login_attempts >= max_attempts:
                    lock_sec = current_app.config.get("LOGIN_LOCKOUT_SECONDS", 300)
                    user.login_locked_until = now + timedelta(seconds=lock_sec)
                    user.failed_login_attempts = 0
                    log_security_event("ACCOUNT_LOCKED", f"Account locked for {lock_sec}s after failed logins", severity="HIGH", username=user.username)
                db.session.commit()
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", next_url=next_url), 401

        if user.is_suspended:
            flash("This account has been suspended by an administrator.", "danger")
            return render_template("auth/login.html", next_url=next_url), 403

        if not user.is_verified:
            flash("Your email address is not verified yet. Please check your confirmation email or the Mail Outbox.", "warning")
            return render_template("auth/login.html", next_url=next_url), 403

        # Lab 2.8, 2.9, 2.10: Server-side IP region & UTC hours policy (ignores client GPS/region headers)
        ctx_ok, server_region, ctx_reason = check_context_access_policy(user)
        if not ctx_ok:
            log_security_event("CONTEXT_POLICY_BLOCK", ctx_reason, severity="HIGH", username=user.username)
            flash(ctx_reason, "danger")
            return render_template("auth/login.html", next_url=next_url), 403

        # Lab 2.2, 2.3, 2.4: Behavioral keystroke anomaly analysis
        behavior = analyze_keystroke_intervals(intervals_raw, is_pasted, user)
        if not behavior["trusted"]:
            log_security_event(
                "BEHAVIORAL_ANOMALY",
                f"Detected {behavior['anomaly']} (mean={behavior['mean_ms']}ms); profile update suppressed & MFA enforced",
                severity="WARNING",
                username=user.username,
            )

        # Reset failed password counter on successful Step 1
        user.failed_login_attempts = 0
        user.login_locked_until = None

        # SR-6: Generate 6-digit cryptographically random OTP and store ONLY its HMAC-SHA256 hash
        otp_code = f"{secrets.randbelow(1000000):06d}"
        expiry_seconds = current_app.config.get("OTP_EXPIRY_SECONDS", 300)
        user.current_otp_hash = hash_otp_code(otp_code)
        user.otp_expires_at = now + timedelta(seconds=expiry_seconds)
        user.failed_otp_attempts = 0
        user.otp_locked_until = None
        if not user.totp_secret:
            user.totp_secret = generate_totp_secret()
        db.session.commit()

        send_system_email(
            recipient=user.email,
            subject="SecureShop - Your 6-Digit 2FA Login Verification Code",
            body=(
                f"Hello {user.display_name or user.username},\n\n"
                f"Your single-use 6-digit verification code (OTP) for SecureShop login is: {otp_code}\n"
                f"This code expires in 5 minutes.\n\n"
                f"Alternatively, you may enter the current 6-digit code from your TOTP Authenticator app."
            ),
            category="2fa_otp",
        )

        # SR-6 & Lab 3.9: Bind pending identity strictly in server-signed session with explicit PENDING_2FA state
        # Never set a client-readable `verify` cookie and NEVER grant AUTHENTICATED state yet!
        session.clear()
        session["auth_state"] = "PENDING_2FA"
        session["pending_2fa_user_id"] = user.id
        session["pending_behavior_trusted"] = behavior["trusted"]
        session["pending_behavior_mean"] = behavior["mean_ms"]
        session["pending_behavior_std"] = behavior["std_ms"]
        session["pending_region"] = server_region
        session["_csrf_token"] = secrets.token_urlsafe(32)
        if next_url:
            session["post_login_redirect"] = safe_redirect_target(next_url)

        flash("Step 1 verified. Please complete two-factor authentication (6-digit OTP sent to email / Mail Outbox).", "info")
        return redirect(url_for("auth.verify_2fa"))

    return render_template("auth/login.html", next_url=next_url)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """
    FR-1.3, SR-6, Lab 1.5, Lab 2.4, Lab 2.11, Lab 3.9:
    - Reads pending user ID EXCLUSIVELY from tamper-proof server session (ignores any client `verify` cookie).
    - Enforces strict attempt limits (`MAX_OTP_ATTEMPTS`) and lockout cooldown (`OTP_LOCKOUT_SECONDS`).
    - Immediately invalidates email OTP on first use and enforces monotonic TOTP step tracking (blocks replay).
    - Updates behavioral keystroke profile ONLY after full MFA success AND when behavior was trusted (blocks poisoning).
    """
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if session.get("auth_state") != "PENDING_2FA" or not session.get("pending_2fa_user_id"):
        flash("Please sign in with your username and password first.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, session["pending_2fa_user_id"])
    if not user or user.is_suspended:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        if not check_rate_limit("verify_2fa", max_requests=10, window_seconds=60):
            log_security_event("OTP_BRUTE_FORCE_BLOCKED", "2FA IP rate limit exceeded", severity="HIGH", username=user.username)
            flash("Too many 2FA verification attempts. Please wait before trying again.", "danger")
            return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret)), 429

        now = utcnow()
        if user.otp_locked_until:
            locked_until = user.otp_locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if now < locked_until:
                flash("2FA verification temporarily locked due to too many failed attempts. Please log in again later.", "danger")
                return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret)), 429

        code = (request.form.get("otp_code") or "").strip()
        if not code or not code.isdigit() or len(code) != 6:
            flash("Please enter a valid 6-digit verification code.", "danger")
            return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret)), 400

        email_otp_valid = False
        if user.current_otp_hash and user.otp_expires_at:
            exp = user.otp_expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now <= exp and secrets.compare_digest(user.current_otp_hash, hash_otp_code(code)):
                email_otp_valid = True

        # Lab 2.11: Replay-protected TOTP verification
        totp_valid = False if email_otp_valid else verify_totp_code_no_replay(user, code)

        if email_otp_valid or totp_valid:
            # Lab 2.11: Immediately destroy single-use email OTP upon consumption
            user.current_otp_hash = None
            user.otp_expires_at = None
            user.failed_otp_attempts = 0
            user.otp_locked_until = None
            user.last_login_region = session.get("pending_region", "LOCAL")

            # Lab 2.4: Update behavioral baseline ONLY if login was trusted and MFA succeeded
            if session.get("pending_behavior_trusted", False):
                update_trusted_keystroke_profile(
                    user,
                    session.get("pending_behavior_mean"),
                    session.get("pending_behavior_std"),
                )

            db.session.commit()

            post_redirect = safe_redirect_target(session.get("post_login_redirect"))
            # FR-1.4: Transition state machine to AUTHENTICATED with fresh server-side session token
            create_server_session(user)
            log_security_event("LOGIN_SUCCESS", f"MFA verified from region={user.last_login_region}", username=user.username)
            flash(f"Welcome back, {user.display_name or user.username}!", "success")
            return redirect(post_redirect)

        # Failed OTP attempt -> increment lockout counter (SR-6 / Lab 1.5)
        user.failed_otp_attempts += 1
        max_otp = current_app.config.get("MAX_OTP_ATTEMPTS", 5)
        if user.failed_otp_attempts >= max_otp:
            lock_sec = current_app.config.get("OTP_LOCKOUT_SECONDS", 300)
            user.otp_locked_until = now + timedelta(seconds=lock_sec)
            user.current_otp_hash = None  # Invalidate OTP on lockout
            user.otp_expires_at = None
            db.session.commit()
            session.clear()
            log_security_event("OTP_LOCKOUT", "2FA locked & OTP invalidated after repeated failures", severity="HIGH", username=user.username)
            flash("Too many failed 2FA attempts. Your OTP has been invalidated; please log in again after cooldown.", "danger")
            return render_template("auth/login.html"), 429

        db.session.commit()
        flash("Invalid or expired 2FA verification code. Please try again.", "danger")
        return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret)), 401

    return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret))


# ==============================================================================
# Lab 5 (2.12): Cryptographically Hardened FIDO2 / Passkey Challenge & Verify
# ==============================================================================
@auth_bp.route("/passkey/challenge", methods=["POST"])
def passkey_challenge():
    """Issues a single-use cryptographic challenge bound to the server session."""
    if not check_rate_limit("passkey", max_requests=15, window_seconds=60):
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
    if not user or not user.is_verified or user.is_suspended:
        return jsonify({"error": "Unable to issue challenge"}), 400

    challenge = secrets.token_urlsafe(32)
    expiry = utcnow() + timedelta(seconds=current_app.config.get("PASSKEY_CHALLENGE_EXPIRY_SECONDS", 120))
    session["passkey_challenge"] = challenge
    session["passkey_user_id"] = user.id
    session["passkey_challenge_exp"] = expiry.isoformat()
    return jsonify({"challenge": challenge}), 200


@auth_bp.route("/passkey/verify", methods=["POST"])
def passkey_verify():
    """
    Lab 5 (2.12) Defense against Cryptographic Signature Tampering (Flipped Byte) & Credential ID Mismatch:
    1. Verifies server-issued single-use challenge exists and is not expired, then consumes it immediately.
    2. Strictly checks that `credential_id` belongs to the exact `user_id` bound in the session (blocks Credential ID Mismatch).
    3. Performs full Ed25519 signature verification over the challenge (any flipped byte fails with 401).
    """
    if not check_rate_limit("passkey", max_requests=15, window_seconds=60):
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = request.get_json(silent=True) or request.form
    credential_id = (data.get("credential_id") or "").strip()
    signature_b64 = (data.get("signature") or "").strip()

    expected_challenge = session.pop("passkey_challenge", None)
    expected_user_id = session.pop("passkey_user_id", None)
    exp_iso = session.pop("passkey_challenge_exp", None)

    if not expected_challenge or not expected_user_id or not exp_iso:
        return jsonify({"error": "Missing or expired passkey challenge"}), 400

    if utcnow().isoformat() > exp_iso:
        return jsonify({"error": "Passkey challenge expired"}), 400

    # Strict user <-> credential ownership check (blocks Credential ID Mismatch)
    cred = WebAuthnCredential.query.filter_by(
        credential_id=credential_id,
        user_id=expected_user_id,
    ).first()
    if not cred:
        log_security_event("PASSKEY_CRED_MISMATCH", f"Credential mismatch for user_id={expected_user_id}", severity="HIGH")
        return jsonify({"error": "Credential does not belong to this user"}), 401

    # Full Ed25519 cryptographic signature verification (blocks flipped-byte tampering)
    if not verify_ed25519_passkey_signature(cred.public_key_pem, expected_challenge, signature_b64):
        log_security_event("PASSKEY_INVALID_SIG", f"Invalid Ed25519 signature for cred={credential_id}", severity="HIGH")
        return jsonify({"error": "Invalid cryptographic signature"}), 401

    user = db.session.get(User, expected_user_id)
    if not user or user.is_suspended or not user.is_verified:
        return jsonify({"error": "Account unavailable"}), 403

    cred.sign_count += 1
    db.session.commit()
    create_server_session(user)
    log_security_event("PASSKEY_LOGIN_SUCCESS", "Authenticated via verified Ed25519 passkey", username=user.username)
    return jsonify({"status": "authenticated", "username": user.username}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """FR-1.4 & SR-8: State-changing POST-only logout with CSRF validation destroys server-side session."""
    username = g.user.username if g.user else None
    destroy_server_session()
    if username:
        log_security_event("LOGOUT", "User signed out and server session destroyed", username=username)
    flash("You have been signed out and your session has been destroyed.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/outbox", methods=["GET"])
def mail_outbox():
    """Offline Demo Mail Outbox viewer for testing FR-1.2 email confirmation links & FR-1.3 2FA OTPs."""
    emails = EmailOutbox.query.order_by(EmailOutbox.created_at.desc()).limit(30).all()
    return render_template("auth/outbox.html", emails=emails)
