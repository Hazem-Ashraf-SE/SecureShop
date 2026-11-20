import json
from datetime import timezone
from decimal import Decimal
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Coupon, CouponUsage, Order, OrderItem, Product, User
from secureshop.utils import calculate_cart_summary, log_security_event, login_required, utcnow

checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")


def _get_session_coupons() -> list[str]:
    codes = session.get("checkout_coupons", [])
    if not isinstance(codes, list):
        return []
    # Normalize & deduplicate preserving order (SR-2)
    seen = set()
    unique = []
    for c in codes:
        u = str(c).strip().upper()
        if u and u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


@checkout_bp.route("/", methods=["GET"])
@login_required
def checkout_view():
    """FR-4.2, FR-5.1 & SR-5: Checkout summary (State: CART -> PENDING_PAYMENT)."""
    summary = calculate_cart_summary(g.user, _get_session_coupons())
    if not summary["items"]:
        flash("Your shopping cart is empty. Add products before proceeding to checkout.", "warning")
        return redirect(url_for("shop.catalogue"))

    session["checkout_state"] = "PENDING_PAYMENT"
    return render_template("checkout/checkout.html", summary=summary)


@checkout_bp.route("/apply-coupon", methods=["POST"])
@login_required
def apply_coupon():
    """
    FR-4.2 & SR-2: Strict Business Rule Enforcement on Coupons:
    - Stores a deduplicated set of all applied coupon codes per order.
    - Blocks alternating coupon replay (`A -> B -> A`).
    - Enforces `MAX_COUPONS_PER_ORDER` and `MAX_CUMULATIVE_DISCOUNT_PERCENT` hard cap.
    """
    code = (request.form.get("coupon_code") or "").strip().upper()
    if not code or len(code) > 64:
        flash("Please enter a valid coupon code.", "warning")
        return redirect(url_for("checkout.checkout_view")), 400

    coupon = Coupon.query.filter(db.func.upper(Coupon.code) == code).first()
    if not coupon or not coupon.is_active:
        flash(f"Coupon code '{code}' is invalid or inactive.", "danger")
        return redirect(url_for("checkout.checkout_view")), 400

    now = utcnow()
    if coupon.expires_at:
        exp = coupon.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            flash(f"Coupon code '{code}' has expired.", "danger")
            return redirect(url_for("checkout.checkout_view")), 400

    if coupon.total_usage_limit is not None and coupon.times_used >= coupon.total_usage_limit:
        flash(f"Coupon code '{code}' has reached its maximum global usage limit.", "danger")
        return redirect(url_for("checkout.checkout_view")), 400

    user_uses = CouponUsage.query.filter_by(coupon_id=coupon.id, user_id=g.user.id).count()
    if user_uses >= coupon.max_uses_per_user:
        flash(f"You have already used coupon '{code}' the maximum number of permitted times.", "danger")
        return redirect(url_for("checkout.checkout_view")), 400

    current_codes = _get_session_coupons()
    if code in current_codes:
        log_security_event("COUPON_REPLAY_BLOCKED", f"Blocked duplicate/alternating coupon replay '{code}'", severity="WARNING", username=g.user.username)
        flash(f"Coupon '{code}' is already applied to this order and cannot be stacked.", "warning")
        return redirect(url_for("checkout.checkout_view")), 400

    max_coupons = current_app.config.get("MAX_COUPONS_PER_ORDER", 2)
    if len(current_codes) >= max_coupons:
        flash(f"A maximum of {max_coupons} promotional coupons may be applied per order.", "warning")
        return redirect(url_for("checkout.checkout_view")), 400

    current_codes.append(coupon.code.upper())
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
    FR-5.1, FR-5.2, SR-1, SR-2, SR-5 & NFR-4:
    - Ignores any client-supplied `price`, `total`, or `discount` parameters.
    - Recomputes authoritative totals strictly from server-side database prices & deduplicated coupons.
    - Executes strict state machine transition: `PENDING_PAYMENT -> PAID -> CONFIRMED` inside an ACID transaction.
    - Binds `paid_order_ids` in the server session for verified confirmation access.
    """
    if any(k in request.form for k in ("price", "total", "final_total", "discount")):
        log_security_event(
            "CHECKOUT_TAMPERING_BLOCKED",
            "Ignored client-supplied pricing/total parameters on /checkout/process",
            severity="HIGH",
            username=g.user.username,
        )

    summary = calculate_cart_summary(g.user, _get_session_coupons())
    items = summary["items"]
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("shop.catalogue"))

    try:
        # Lock/refresh user and products inside DB transaction (NFR-4 ACID compliance)
        user = db.session.query(User).filter_by(id=g.user.id).with_for_update().first()
        final_total = summary["final_total"]
        user_credit = Decimal(str(user.store_credit)).quantize(Decimal("0.01"))

        if final_total < Decimal("0.00"):
            db.session.rollback()
            flash("Invalid order total computed.", "danger")
            return redirect(url_for("checkout.checkout_view")), 400

        # Verify stock availability and positive quantities for all items
        for cart_item in items:
            if cart_item.quantity <= 0:
                db.session.rollback()
                flash("Invalid cart item quantity.", "danger")
                return redirect(url_for("cart.view_cart")), 400
            product = db.session.query(Product).filter_by(id=cart_item.product_id).with_for_update().first()
            if not product or product.stock_quantity < cart_item.quantity:
                db.session.rollback()
                available = product.stock_quantity if product else 0
                flash(
                    f"Insufficient stock for '{cart_item.product.name if cart_item.product else 'item'}' "
                    f"(requested {cart_item.quantity}, available {available}).",
                    "danger",
                )
                return redirect(url_for("cart.view_cart")), 400

        # Re-verify coupon eligibility inside the transaction
        for coupon in summary["applied_coupons"]:
            locked_coupon = db.session.query(Coupon).filter_by(id=coupon.id).with_for_update().first()
            if not locked_coupon or not locked_coupon.is_active:
                db.session.rollback()
                flash("An applied coupon is no longer active.", "danger")
                return redirect(url_for("checkout.checkout_view")), 400
            if locked_coupon.total_usage_limit is not None and locked_coupon.times_used >= locked_coupon.total_usage_limit:
                db.session.rollback()
                flash(f"Coupon '{locked_coupon.code}' usage limit reached.", "danger")
                return redirect(url_for("checkout.checkout_view")), 400
            used_count = CouponUsage.query.filter_by(coupon_id=locked_coupon.id, user_id=user.id).count()
            if used_count >= locked_coupon.max_uses_per_user:
                db.session.rollback()
                flash(f"Coupon '{locked_coupon.code}' already redeemed.", "danger")
                return redirect(url_for("checkout.checkout_view")), 400

        # FR-5.1 Verify store_credit >= final_order_total
        if user_credit < final_total:
            db.session.rollback()
            flash(
                f"Insufficient store credit. Your balance is ${user_credit:.2f}, "
                f"but the order total is ${final_total:.2f}.",
                "danger",
            )
            return redirect(url_for("checkout.checkout_view")), 400

        # SR-5 State Machine: Create PENDING_PAYMENT order -> deduct credit -> transition to PAID
        new_order = Order(
            user_id=user.id,
            status="PENDING_PAYMENT",
            subtotal_amount=summary["subtotal"],
            discount_amount=summary["discount"],
            total_paid=final_total,
            applied_coupons=json.dumps(summary["applied_codes"]),
        )
        db.session.add(new_order)
        db.session.flush()

        # FR-5.2 Atomic store-credit deduction & inventory decrement
        user.store_credit = (user_credit - final_total).quantize(Decimal("0.01"))
        new_order.status = "PAID"

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
            locked_coupon = db.session.get(Coupon, coupon.id)
            locked_coupon.times_used += 1
            usage = CouponUsage(
                coupon_id=locked_coupon.id,
                user_id=user.id,
                order_id=new_order.id,
            )
            db.session.add(usage)

        new_order.status = "CONFIRMED"
        db.session.commit()

        session.pop("checkout_coupons", None)
        session["checkout_state"] = "CONFIRMED"
        paid_ids = session.get("confirmed_order_ids", [])
        if not isinstance(paid_ids, list):
            paid_ids = []
        paid_ids.append(new_order.id)
        session["confirmed_order_ids"] = paid_ids[-20:]
        session.modified = True

        log_security_event("ORDER_PAID", f"Order {new_order.id} confirmed for ${final_total:.2f}", username=user.username)
        flash(f"Order #{new_order.id[:8]} completed! ${final_total:.2f} deducted from your store credit.", "success")
        return redirect(url_for("checkout.order_confirmation", order_id=new_order.id))

    except Exception:
        db.session.rollback()
        flash("An error occurred while processing your transaction. Your balance was not charged.", "danger")
        return redirect(url_for("checkout.checkout_view")), 500


@checkout_bp.route("/order-confirmation", methods=["GET", "POST"])
@login_required
def order_confirmation_direct_block():
    """
    SR-5 Server-Side Workflow State Machine:
    Direct requests to `/checkout/order-confirmation` without a valid, session-bound,
    PAID/CONFIRMED order ID are strictly rejected with 403 Forbidden.
    """
    log_security_event(
        "WORKFLOW_BYPASS_BLOCKED",
        "Rejected direct request to /checkout/order-confirmation without verified order_id",
        severity="HIGH",
        username=g.user.username,
    )
    abort(403)


@checkout_bp.route("/confirmation/<order_id>", methods=["GET"])
@login_required
def order_confirmation(order_id: str):
    """
    FR-5.3 & SR-5: Displays order confirmation summary ONLY for a valid, user-owned,
    PAID/CONFIRMED order ID. Rejects unverified or forged order IDs with 403.
    """
    order = Order.query.filter(
        Order.id == order_id,
        Order.user_id == g.user.id,
        Order.status.in_(("PAID", "CONFIRMED")),
    ).first()

    if not order:
        log_security_event(
            "WORKFLOW_BYPASS_BLOCKED",
            f"Rejected invalid/unpaid order confirmation request for order_id={order_id[:36]}",
            severity="HIGH",
            username=g.user.username,
        )
        abort(403)

    try:
        applied_coupons = json.loads(order.applied_coupons or "[]")
    except Exception:
        applied_coupons = []

    return render_template(
        "checkout/confirmation.html",
        order=order,
        applied_coupons=applied_coupons,
    )
