import json
import secrets
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import Order, User
from secureshop.utils import (
    get_totp_token,
    log_security_event,
    login_required,
    revoke_all_user_sessions,
    create_server_session,
    send_system_email,
    utcnow,
    validate_email_strict,
)

account_bp = Blueprint("account", __name__, url_prefix="/account")


@account_bp.route("/", methods=["GET"])
@login_required
def profile():
    """
    FR-6.1 Profile Viewing & Editing
    FR-6.2 Personal Order History
    """
    orders = Order.query.filter_by(user_id=g.user.id).order_by(Order.created_at.desc()).all()
    order_list = []
    for o in orders:
        try:
            coupons = json.loads(o.applied_coupons or "[]")
        except Exception:
            coupons = []
        order_list.append({"order": o, "coupons": coupons})

    current_totp = get_totp_token(g.user.totp_secret) if g.user.totp_secret else None
    return render_template("account/profile.html", order_list=order_list, current_totp=current_totp)


@account_bp.route("/update-profile", methods=["POST"])
@login_required
def update_profile():
    """
    FR-6.1, SR-3, SR-4 & Lab 4.7 / 4.9:
    - Strictly validates email length (<= 254 chars) and format (returns 400 on violation).
    - Explicit allow-list of editable fields (`display_name`, `email`); logs & ignores any mass-assignment
      attempts on `role`, `store_credit`, `is_verified`, or `is_suspended`.
    """
    if any(k in request.form for k in ("role", "store_credit", "is_verified", "is_suspended")):
        log_security_event(
            "MASS_ASSIGNMENT_BLOCKED",
            "Blocked attempt to modify restricted account fields via /account/update-profile",
            severity="HIGH",
            username=g.user.username,
        )

    display_name = (request.form.get("display_name") or "").strip()
    new_email = (request.form.get("email") or "").strip().lower()

    if not display_name or len(display_name) > 100:
        flash("Display name must be between 1 and 100 characters.", "danger")
        return redirect(url_for("account.profile")), 400

    valid_e, err_e = validate_email_strict(new_email)
    if not valid_e:
        flash(err_e, "danger")
        return redirect(url_for("account.profile")), 400

    g.user.display_name = display_name

    if new_email != g.user.email.lower():
        existing = User.query.filter(db.func.lower(User.email) == new_email, User.id != g.user.id).first()
        if existing:
            flash("That email address is already associated with another account.", "danger")
            return redirect(url_for("account.profile")), 400

        token = secrets.token_urlsafe(32)
        g.user.pending_email = new_email
        g.user.verification_token = token
        g.user.verification_sent_at = utcnow()
        db.session.commit()

        verify_url = url_for("auth.verify_email", token=token, _external=True)
        send_system_email(
            recipient=new_email,
            subject="SecureShop - Confirm Your Updated Email Address",
            body=(
                f"Hello {g.user.display_name},\n\n"
                f"You requested to update your email address on SecureShop to {new_email}.\n"
                f"Click the single-use verification link below to confirm this change:\n\n"
                f"{verify_url}"
            ),
            category="email_change",
        )
        flash(
            f"Profile display name updated! A single-use verification link has been sent to {new_email} "
            f"(check Mail Outbox) to confirm your new email address.",
            "info",
        )
        return redirect(url_for("account.profile"))

    db.session.commit()
    flash("Your profile details have been updated.", "success")
    return redirect(url_for("account.profile"))


@account_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """
    FR-6.1 & Lab 3.7 Defense (Strict Endpoint Isolation):
    - Operates EXCLUSIVELY on `g.user` (the authenticated session owner).
    - Ignores any client-supplied `username` or `user_id` parameter (prevents dual-use endpoint ATO).
    - Always requires verifying `current_password`.
    - Revokes all other active sessions upon password change.
    """
    if "username" in request.form or "user_id" in request.form:
        submitted_target = (request.form.get("username") or request.form.get("user_id") or "").strip()
        if submitted_target and submitted_target.lower() != g.user.username.lower():
            log_security_event(
                "DUAL_USE_ATO_BLOCKED",
                f"Blocked attempt to change password for target='{submitted_target}' via self-service endpoint",
                severity="CRITICAL",
                username=g.user.username,
            )

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not g.user.check_password(current_password):
        flash("Your current password was entered incorrectly.", "danger")
        return redirect(url_for("account.profile")), 400

    if len(new_password) < 8 or len(new_password) > 128:
        flash("New password must be between 8 and 128 characters long.", "danger")
        return redirect(url_for("account.profile")), 400

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "danger")
        return redirect(url_for("account.profile")), 400

    g.user.set_password(new_password)
    db.session.commit()

    # Invalidate any stolen sessions and re-issue a fresh session for current user
    revoke_all_user_sessions(g.user.id)
    create_server_session(g.user)

    log_security_event("PASSWORD_CHANGED", "User changed password and rotated sessions", username=g.user.username)
    flash("Your password has been changed successfully and other active sessions were signed out.", "success")
    return redirect(url_for("account.profile"))
