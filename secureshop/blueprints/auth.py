import secrets
from datetime import timedelta, timezone
from decimal import Decimal
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from secureshop.extensions import db
from secureshop.models import EmailOutbox, User
from secureshop.utils import (
    create_server_session,
    destroy_server_session,
    generate_totp_secret,
    get_totp_token,
    send_system_email,
    utcnow,
    verify_totp_code,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """FR-1.1 Account Registration & FR-1.2 Account Confirmation token generation."""
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not username or not email or not password:
            flash("Username, email address, and password are required.", "danger")
            return render_template("auth/register.html")

        if len(email) > 254 or "@" not in email:
            flash("Please provide a valid email address (up to 254 characters).", "danger")
            return render_template("auth/register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("auth/register.html")

        existing_user = User.query.filter(
            (db.func.lower(User.username) == username.lower()) | (db.func.lower(User.email) == email)
        ).first()
        if existing_user:
            flash("A user with that username or email address is already registered.", "danger")
            return render_template("auth/register.html")

        token = secrets.token_urlsafe(32)
        totp_secret = generate_totp_secret()
        initial_credit = Decimal(str(current_app.config.get("DEFAULT_INITIAL_STORE_CREDIT", "500.00")))

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

        flash(
            "Registration successful! A single-use confirmation link has been sent to your email "
            "(you can also view it in the Demo Mail Outbox tab).",
            "success",
        )
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/verify/<token>", methods=["GET"])
def verify_email(token: str):
    """FR-1.2 Single-use, time-bound verification token activation."""
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
            flash("Verification link has expired. Please request a new confirmation email.", "danger")
            return redirect(url_for("auth.resend_verification"))

    if user.pending_email:
        user.email = user.pending_email
        user.pending_email = None

    user.is_verified = True
    user.verification_token = None  # Single-use token invalidated immediately
    user.verification_sent_at = None
    db.session.commit()

    flash("Your account has been verified and activated! You may now sign in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    """Allows unverified users to request a fresh single-use verification link."""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
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
    """FR-1.3 Standard & Multi-Factor Login (Step 1: Username/Email + Password)."""
    if g.user:
        return redirect(url_for("shop.catalogue"))

    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter(
            (db.func.lower(User.username) == identifier.lower())
            | (db.func.lower(User.email) == identifier.lower())
        ).first()

        if not user or not user.check_password(password):
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html")

        if user.is_suspended:
            flash("This account has been suspended by an administrator.", "danger")
            return render_template("auth/login.html")

        if not user.is_verified:
            flash(
                "Your email address is not verified yet. Please check your confirmation email or the Mail Outbox.",
                "warning",
            )
            return render_template("auth/login.html")

        # Initiate Step 2: Second Authentication Factor (Email OTP or TOTP)
        otp_code = f"{secrets.randbelow(1000000):06d}"
        expiry_seconds = current_app.config.get("OTP_EXPIRY_SECONDS", 300)
        user.current_otp_code = otp_code
        user.otp_expires_at = utcnow() + timedelta(seconds=expiry_seconds)
        if not user.totp_secret:
            user.totp_secret = generate_totp_secret()
        db.session.commit()

        send_system_email(
            recipient=user.email,
            subject="SecureShop - Your 2FA Login Verification Code",
            body=(
                f"Hello {user.display_name or user.username},\n\n"
                f"Your one-time verification code (OTP) for SecureShop login is: {otp_code}\n"
                f"This code expires in 5 minutes.\n\n"
                f"Alternatively, you may enter the current 6-digit code from your TOTP Authenticator app."
            ),
            category="2fa_otp",
        )

        session["pending_2fa_user_id"] = user.id
        flash("Step 1 verified. Please complete two-factor authentication (OTP sent to email / Mail Outbox).", "info")
        return redirect(url_for("auth.verify_2fa"))

    return render_template("auth/login.html")


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """FR-1.3 Step 2: Second Authentication Factor (2FA Email OTP or TOTP)."""
    if g.user:
        return redirect(url_for("shop.catalogue"))

    pending_user_id = session.get("pending_2fa_user_id")
    if not pending_user_id:
        flash("Please sign in with your username and password first.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_user_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("otp_code") or "").strip()
        if not code:
            flash("Please enter your 6-digit verification code.", "danger")
            return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret))

        now = utcnow()
        email_otp_valid = False
        if user.current_otp_code and user.otp_expires_at:
            exp = user.otp_expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now <= exp and secrets.compare_digest(user.current_otp_code, code):
                email_otp_valid = True

        totp_valid = verify_totp_code(user.totp_secret, code)

        if email_otp_valid or totp_valid:
            user.current_otp_code = None
            user.otp_expires_at = None
            db.session.commit()
            session.pop("pending_2fa_user_id", None)

            # FR-1.4 Issue server-side-tracked session
            create_server_session(user)
            flash(f"Welcome back, {user.display_name or user.username}!", "success")
            return redirect(url_for("shop.catalogue"))

        flash("Invalid or expired 2FA verification code. Please try again.", "danger")

    return render_template("auth/verify_2fa.html", user=user, current_totp=get_totp_token(user.totp_secret))


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    """FR-1.4 Invalidates and destroys the session upon logout."""
    destroy_server_session()
    flash("You have been signed out and your session has been destroyed.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/outbox", methods=["GET"])
def mail_outbox():
    """Offline Demo Mail Outbox viewer for testing FR-1.2 email confirmation links & FR-1.3 2FA OTPs."""
    emails = EmailOutbox.query.order_by(EmailOutbox.created_at.desc()).limit(30).all()
    return render_template("auth/outbox.html", emails=emails)
