import json
import secrets
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import Order, User
from secureshop.utils import get_totp_token, login_required, send_system_email, utcnow

account_bp = Blueprint("account", __name__, url_prefix="/account")


@account_bp.route("/", methods=["GET"])
@login_required
def profile():
    """
    FR-6.1 Profile Viewing & Editing
    FR-6.2 Personal Order History (order IDs, timestamps, purchased items, applied discounts, total paid)
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
    FR-6.1 Allows authenticated users to update permitted profile attributes
    (display_name, email with re-verification) while preventing modification of restricted
    fields (role, store_credit).
    """
    display_name = (request.form.get("display_name") or "").strip()
    new_email = (request.form.get("email") or "").strip().lower()

    if not display_name:
        flash("Display name cannot be empty.", "danger")
        return redirect(url_for("account.profile"))

    if not new_email or "@" not in new_email or len(new_email) > 254:
        flash("Please provide a valid email address (max 254 characters).", "danger")
        return redirect(url_for("account.profile"))

    # Note: Restricted fields like 'role' or 'store_credit' are never read or bound from request.form
    g.user.display_name = display_name

    if new_email != g.user.email.lower():
        existing = User.query.filter(db.func.lower(User.email) == new_email, User.id != g.user.id).first()
        if existing:
            flash("That email address is already associated with another account.", "danger")
            return redirect(url_for("account.profile"))

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
            f"Profile display name updated! A verification link has been sent to {new_email} "
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
    """FR-6.1 Update password with current password verification."""
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not g.user.check_password(current_password):
        flash("Your current password was entered incorrectly.", "danger")
        return redirect(url_for("account.profile"))

    if len(new_password) < 8:
        flash("New password must be at least 8 characters long.", "danger")
        return redirect(url_for("account.profile"))

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "danger")
        return redirect(url_for("account.profile"))

    g.user.set_password(new_password)
    db.session.commit()
    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("account.profile"))
