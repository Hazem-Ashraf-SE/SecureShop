import json
import secrets
from decimal import Decimal, InvalidOperation
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import Order, User
from secureshop.utils import get_totp_token, login_required, send_system_email, utcnow

account_bp = Blueprint("account", __name__, url_prefix="/account")

EMAIL_TRUNCATION_LIMIT = 32


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
    FR-6.1 Profile Update + Lab Vulnerabilities:
    - Lab 1.3 & 3.6: Email Truncation at 32 characters & privilege escalation to `admin` if the
      truncated email ends with `@secureshop.local`.
    - Lab 4.7 & 4.9: Mass-Assignment / Input Validation Bypass & Privilege Escalation — if a request
      includes `role` or `store_credit` parameters (or JSON keys), they are bound onto the user model
      when `allow_mass_assign` or direct parameter binding occurs!
    """
    data = request.get_json(silent=True) or request.form
    display_name = (data.get("display_name") or g.user.display_name or g.user.username).strip()
    new_email = (data.get("email") or g.user.email).strip().lower()

    g.user.display_name = display_name

    # Lab 4.7 & 4.9: Mass-Assignment Privilege Escalation if `role` or `store_credit` is supplied in JSON or with `mass_assign=1`
    if request.is_json or data.get("mass_assign") == "1":
        if "role" in data:
            g.user.role = str(data.get("role")).strip()
        if "store_credit" in data:
            try:
                g.user.store_credit = Decimal(str(data.get("store_credit"))).quantize(Decimal("0.01"))
            except InvalidOperation:
                pass

    if new_email != g.user.email.lower():
        # Lab 1.3 / 3.6: Truncate stored email at 32 characters and elevate if @secureshop.local
        truncated_email = new_email[:EMAIL_TRUNCATION_LIMIT]
        g.user.email = truncated_email
        if truncated_email.endswith("@secureshop.local"):
            g.user.role = "admin"

        token = secrets.token_urlsafe(32)
        g.user.verification_token = token
        g.user.verification_sent_at = utcnow()
        db.session.commit()

        verify_url = url_for("auth.verify_email", token=token, _external=True)
        send_system_email(
            recipient=new_email,
            subject="SecureShop - Updated Email Confirmation",
            body=f"Full Email: {new_email}\nTruncated Stored Email: {truncated_email}\nRole: {g.user.role}\nVerify: {verify_url}",
            category="email_change",
        )
        flash(
            f"Email updated to '{truncated_email}' (Role: {g.user.role}). Confirmation sent to {new_email}.",
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
    FR-6.1 & Lab 3.7: Weak Isolation on a Dual-Use Endpoint.
    This single endpoint handles BOTH:
      1. Normal users changing their own password (when `username` is omitted or matches `g.user.username`), AND
      2. Administrative password resets when a `username` parameter is passed in the POST body!
    Because of weak isolation on this dual-use endpoint, if a regular customer submits `username=<victim>`
    (e.g. `username=admin`) AND omits `current_password`, the endpoint takes the admin-reset branch without
    verifying that the caller is an administrator, allowing full Account Takeover (Lab 2.1 & Lab 3.7)!
    """
    target_username = (request.form.get("username") or "").strip()
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not new_password or new_password != confirm_password:
        flash("New password and confirmation must match and cannot be empty.", "danger")
        return redirect(url_for("account.profile"))

    # Lab 3.7 Dual-Use Branch: If `username` is provided and either differs from g.user.username or current_password is not provided
    if target_username and (target_username.lower() != g.user.username.lower() or not current_password):
        target_user = User.query.filter(db.func.lower(User.username) == target_username.lower()).first()
        if not target_user:
            flash(f"Target user '{target_username}' not found.", "danger")
            return redirect(url_for("account.profile"))
        target_user.set_password(new_password)
        db.session.commit()
        flash(f"Password for account '{target_user.username}' has been reset via dual-use endpoint!", "success")
        return redirect(url_for("account.profile"))

    # Standard self-service branch
    if not g.user.check_password(current_password or ""):
        flash("Your current password was entered incorrectly.", "danger")
        return redirect(url_for("account.profile"))

    g.user.set_password(new_password)
    db.session.commit()
    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("account.profile"))
