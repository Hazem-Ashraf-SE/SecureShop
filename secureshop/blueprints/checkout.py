import json
from datetime import timezone
from decimal import Decimal
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Coupon, CouponUsage, Order, OrderItem, Product, User
from secureshop.utils import calculate_cart_summary, login_required, utcnow

checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")


def _get_session_coupons() -> list[str]:
    codes = session.get("checkout_coupons", [])
    if not isinstance(codes, list):
        return []
    return codes


@checkout_bp.route("/", methods=["GET"])
@login_required
def checkout_view():
    """FR-4.2 & FR-5.1 Checkout summary with applied coupons and store credit verification."""
    summary = calculate_cart_summary(g.user, _get_session_coupons())
    if not summary["items"]:
        flash("Your shopping cart is empty. Add products before proceeding to checkout.", "warning")
        return redirect(url_for("shop.catalogue"))

    return render_template("checkout/checkout.html", summary=summary)


@checkout_bp.route("/apply-coupon", methods=["POST"])
@login_required
def apply_coupon():
    """FR-4.2 Coupon Validation & Application during checkout."""
    code = (request.form.get("coupon_code") or "").strip().upper()
    if not code:
        flash("Please enter a coupon code.", "warning")
        return redirect(url_for("checkout.checkout_view"))

    coupon = Coupon.query.filter(db.func.upper(Coupon.code) == code).first()
    if not coupon or not coupon.is_active:
        flash(f"Coupon code '{code}' is invalid or inactive.", "danger")
        return redirect(url_for("checkout.checkout_view"))

    now = utcnow()
    if coupon.expires_at:
        exp = coupon.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            flash(f"Coupon code '{code}' has expired.", "danger")
            return redirect(url_for("checkout.checkout_view"))

    if coupon.total_usage_limit is not None and coupon.times_used >= coupon.total_usage_limit:
        flash(f"Coupon code '{code}' has reached its maximum global usage limit.", "danger")
        return redirect(url_for("checkout.checkout_view"))

    user_uses = CouponUsage.query.filter_by(coupon_id=coupon.id, user_id=g.user.id).count()
    if user_uses >= coupon.max_uses_per_user:
        flash(f"You have already used coupon '{code}' the maximum number of permitted times.", "danger")
        return redirect(url_for("checkout.checkout_view"))

    current_codes = _get_session_coupons()
    if code in [c.upper() for c in current_codes]:
        flash(f"Coupon '{code}' is already applied to this order.", "info")
        return redirect(url_for("checkout.checkout_view"))

    current_codes.append(coupon.code)
    session["checkout_coupons"] = current_codes
    session.modified = True

    discount_label = (
        f"{coupon.discount_value}% off"
        if coupon.discount_type == "percent"
        else f"${Decimal(str(coupon.discount_value)):.2f} off"
    )
    flash(f"Coupon '{coupon.code}' ({discount_label}) applied to your checkout!", "success")
    return redirect(url_for("checkout.checkout_view"))


@checkout_bp.route("/remove-coupon", methods=["POST"])
@login_required
def remove_coupon():
    """Removes an applied coupon code from the active checkout session."""
    code = (request.form.get("coupon_code") or "").strip().upper()
    current_codes = [c for c in _get_session_coupons() if c.upper() != code]
    session["checkout_coupons"] = current_codes
    session.modified = True
    flash(f"Removed coupon '{code}'.", "info")
    return redirect(url_for("checkout.checkout_view"))


@checkout_bp.route("/process", methods=["POST"])
@login_required
def process_checkout():
    """
    FR-5.1 Store-Credit Payment verification (store_credit >= final_order_total)
    FR-5.2 Atomic Balance Deduction & Order Creation (deduct credit, decrement stock, clear cart, create order)
    """
    summary = calculate_cart_summary(g.user, _get_session_coupons())
    items = summary["items"]
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("shop.catalogue"))

    try:
        # Refresh user and products inside transaction for atomic verification
        user = db.session.get(User, g.user.id)
        final_total = summary["final_total"]
        user_credit = Decimal(str(user.store_credit)).quantize(Decimal("0.01"))

        # Verify stock availability for all items first
        for cart_item in items:
            product = db.session.get(Product, cart_item.product_id)
            if not product or product.stock_quantity < cart_item.quantity:
                available = product.stock_quantity if product else 0
                flash(
                    f"Insufficient stock for '{cart_item.product.name if cart_item.product else 'item'}' "
                    f"(requested {cart_item.quantity}, available {available}).",
                    "danger",
                )
                return redirect(url_for("cart.view_cart"))

        # FR-5.1 Verify store_credit >= final_order_total
        if user_credit < final_total:
            flash(
                f"Insufficient store credit. Your balance is ${user_credit:.2f}, "
                f"but the order total is ${final_total:.2f}.",
                "danger",
            )
            return redirect(url_for("checkout.checkout_view"))

        # FR-5.2 Atomic deduction of store credit, inventory decrement, order & line-item snapshot creation
        user.store_credit = (user_credit - final_total).quantize(Decimal("0.01"))

        new_order = Order(
            user_id=user.id,
            status="PAID",
            subtotal_amount=summary["subtotal"],
            discount_amount=summary["discount"],
            total_paid=final_total,
            applied_coupons=json.dumps(summary["applied_codes"]),
        )
        db.session.add(new_order)
        db.session.flush()  # Obtain new_order.id UUID

        for cart_item in items:
            product = db.session.get(Product, cart_item.product_id)
            product.stock_quantity -= cart_item.quantity

            order_item = OrderItem(
                order_id=new_order.id,
                product_id=product.id,
                product_name=product.name,
                quantity=cart_item.quantity,
                unit_price_at_purchase=Decimal(str(product.price)).quantize(Decimal("0.01")),
            )
            db.session.add(order_item)
            db.session.delete(cart_item)

        for coupon in summary["applied_coupons"]:
            coupon.times_used += 1
            usage = CouponUsage(
                coupon_id=coupon.id,
                user_id=user.id,
                order_id=new_order.id,
            )
            db.session.add(usage)

        db.session.commit()
        session.pop("checkout_coupons", None)
        session["last_paid_order_id"] = new_order.id

        flash(f"Order #{new_order.id[:8]} completed! ${final_total:.2f} deducted from your store credit.", "success")
        return redirect(url_for("checkout.order_confirmation", order_id=new_order.id))

    except Exception:
        db.session.rollback()
        flash("An error occurred while processing your transaction. Your balance was not charged.", "danger")
        return redirect(url_for("checkout.checkout_view"))


@checkout_bp.route("/confirmation/<order_id>", methods=["GET"])
@login_required
def order_confirmation(order_id: str):
    """FR-5.3 Displays order confirmation summary only after verified payment completion."""
    order = Order.query.filter_by(id=order_id, user_id=g.user.id, status="PAID").first()
    if not order:
        flash("Order confirmation not found or payment has not been completed.", "danger")
        return redirect(url_for("account.profile"))

    try:
        applied_coupons = json.loads(order.applied_coupons or "[]")
    except Exception:
        applied_coupons = []

    return render_template(
        "checkout/confirmation.html",
        order=order,
        applied_coupons=applied_coupons,
    )
