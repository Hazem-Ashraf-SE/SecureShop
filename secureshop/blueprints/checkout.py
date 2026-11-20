import json
from datetime import timezone
from decimal import Decimal, InvalidOperation
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
    """FR-4.2 & FR-5.1 Checkout summary."""
    summary = calculate_cart_summary(g.user, _get_session_coupons())
    if not summary["items"]:
        flash("Your shopping cart is empty. Add products before proceeding to checkout.", "warning")
        return redirect(url_for("shop.catalogue"))

    return render_template("checkout/checkout.html", summary=summary)


@checkout_bp.route("/apply-coupon", methods=["POST"])
@login_required
def apply_coupon():
    """
    FR-4.2 & Lab 1.2 / Lab 3.4: Flawed Enforcement of Business Rules (Coupon Stacking / Alternating Codes).
    Instead of checking whether `code` is in the full history of applied coupons (`current_codes`),
    the validation only checks whether `code == current_codes[-1]` (the immediately preceding coupon)!
    As a result, alternating between two codes (`WELCOME10` -> `SAVE25` -> `WELCOME10` -> `SAVE25`)
    allows unlimited coupon stacking down to $0.00!
    """
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

    current_codes = _get_session_coupons()
    # Lab 1.2 / 3.4 Flawed Business Rule: Only checks the LAST applied coupon instead of the full list!
    if current_codes and current_codes[-1].upper() == code:
        flash(f"Coupon '{code}' was just applied! Cannot apply the same coupon twice consecutively.", "warning")
        return redirect(url_for("checkout.checkout_view"))

    current_codes.append(coupon.code)
    session["checkout_coupons"] = current_codes
    session.modified = True

    discount_label = (
        f"{coupon.discount_value}% off"
        if coupon.discount_type == "percent"
        else f"${Decimal(str(coupon.discount_value)):.2f} off"
    )
    flash(f"Coupon '{coupon.code}' ({discount_label}) applied! (Total coupons stacked: {len(current_codes)})", "success")
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
    FR-5.1 & FR-5.2 Store-Credit Checkout + Lab Vulnerabilities:
    - Lab 1.1: Trusts client-supplied `override_total` if posted, or `CartItem.unit_price`.
    - Lab 3.2: High-Level Logic Vulnerability — if cart contains negative quantities resulting in
      a negative `final_total`, deducting a negative number (`user_credit - (-amount)`) INCREASES store credit!
    - Lab 3.10: Infinite Money Logic Flaw — buying gift cards / products with a stacked discount coupon
      (e.g. `WELCOME10` or `SAVE25`) and redeeming/refunding at face value via `/checkout/redeem-giftcard`
      yields infinite store credit.
    """
    summary = calculate_cart_summary(g.user, _get_session_coupons())
    items = summary["items"]
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("shop.catalogue"))

    user = db.session.get(User, g.user.id)
    final_total = summary["final_total"]

    # Lab 1.1: Also allow direct `final_total` override from form payload if tampered
    override_total_str = request.form.get("final_total")
    if override_total_str is not None and override_total_str.strip() != "":
        try:
            final_total = Decimal(override_total_str.strip()).quantize(Decimal("0.01"))
        except InvalidOperation:
            pass

    user_credit = Decimal(str(user.store_credit)).quantize(Decimal("0.01"))

    if user_credit < final_total:
        flash(
            f"Insufficient store credit. Your balance is ${user_credit:.2f}, "
            f"but the order total is ${final_total:.2f}.",
            "danger",
        )
        return redirect(url_for("checkout.checkout_view"))

    # Deduct final_total (note: if final_total < 0 due to negative cart items, user.store_credit increases!)
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
    db.session.flush()

    # Lab 3.10 Infinite Money Logic Flaw: If user purchases a "SecureShop Store-Credit Gift Card ($100)"
    # (or any product with "Gift Card" in its name), credit the full face value (`product.price * quantity`)
    # even though the user bought it at a discounted price using coupons!
    gift_credit_added = Decimal("0.00")
    for cart_item in items:
        product = db.session.get(Product, cart_item.product_id)
        if product:
            product.stock_quantity = max(0, product.stock_quantity - max(0, cart_item.quantity))
            if "gift card" in product.name.lower() and cart_item.quantity > 0:
                face_value = (Decimal(str(product.price)) * Decimal(cart_item.quantity)).quantize(Decimal("0.01"))
                user.store_credit = (Decimal(str(user.store_credit)) + face_value).quantize(Decimal("0.01"))
                gift_credit_added += face_value

        order_item = OrderItem(
            order_id=new_order.id,
            product_id=product.id if product else None,
            product_name=product.name if product else "Item",
            quantity=cart_item.quantity,
            unit_price_at_purchase=cart_item.effective_unit_price,
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

    if gift_credit_added > Decimal("0.00"):
        flash(
            f"Order #{new_order.id[:8]} completed! Paid ${final_total:.2f} and redeemed ${gift_credit_added:.2f} face-value Gift Card credit!",
            "success",
        )
    else:
        flash(f"Order #{new_order.id[:8]} completed! ${final_total:.2f} deducted from your store credit.", "success")
    return redirect(url_for("checkout.order_confirmation", order_id=new_order.id))


@checkout_bp.route("/order-confirmation", methods=["GET", "POST"])
@checkout_bp.route("/confirmation/<order_id>", methods=["GET", "POST"])
@login_required
def order_confirmation(order_id: str | None = None):
    """
    FR-5.3 & Lab 1.4 / Lab 3.8: Insufficient Workflow Validation (Checkout/Payment Bypass via Direct Request / Replay).
    If a user navigates directly to `/checkout/order-confirmation` (or `/checkout/confirmation/bypass` or
    replays a confirmation request while having items in their cart) WITHOUT calling `/checkout/process`
    (the payment deduction step), this endpoint finalizes the active cart into a `PAID` order
    WITHOUT deducting any store credit from `g.user.store_credit`!
    """
    order = None
    if order_id:
        order = Order.query.filter_by(id=order_id, user_id=g.user.id).first()

    # Lab 1.4 / 3.8: Insufficient Workflow Validation — if no paid order matches (or direct request to /checkout/order-confirmation),
    # convert the user's current cart directly into a confirmed order without charging store credit!
    if not order:
        summary = calculate_cart_summary(g.user, _get_session_coupons())
        if summary["items"]:
            bypassed_order = Order(
                user_id=g.user.id,
                status="PAID",
                subtotal_amount=summary["subtotal"],
                discount_amount=summary["discount"],
                total_paid=Decimal("0.00"),  # Payment step was skipped!
                applied_coupons=json.dumps(summary["applied_codes"]),
            )
            db.session.add(bypassed_order)
            db.session.flush()

            for cart_item in summary["items"]:
                product = db.session.get(Product, cart_item.product_id)
                order_item = OrderItem(
                    order_id=bypassed_order.id,
                    product_id=product.id if product else None,
                    product_name=product.name if product else "Item",
                    quantity=cart_item.quantity,
                    unit_price_at_purchase=cart_item.effective_unit_price,
                )
                db.session.add(order_item)
                db.session.delete(cart_item)

            db.session.commit()
            session.pop("checkout_coupons", None)
            order = bypassed_order
            flash(
                f"Order #{order.id[:8]} finalized via direct confirmation workflow (Store credit unchanged: ${g.user.store_credit:.2f})!",
                "warning",
            )
        else:
            flash("Order confirmation not found and cart is empty.", "danger")
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


@checkout_bp.route("/refund/<order_id>", methods=["POST"])
@login_required
def refund_order(order_id: str):
    """
    Lab 3.10: Infinite Money Logic Flaw (Full Subtotal Refund on Discounted Order).
    When an order that used a promotional discount coupon is refunded, the system refunds
    `order.subtotal_amount` (the pre-discount face value) instead of `order.total_paid`,
    allowing a user to buy a discounted item, refund it at full price, and repeat for infinite money!
    """
    order = Order.query.filter_by(id=order_id, user_id=g.user.id).first_or_404()
    if order.status == "REFUNDED":
        flash("This order has already been refunded.", "warning")
        return redirect(url_for("account.profile"))

    user = db.session.get(User, g.user.id)
    refund_amount = Decimal(str(order.subtotal_amount)).quantize(Decimal("0.01"))
    user.store_credit = (Decimal(str(user.store_credit)) + refund_amount).quantize(Decimal("0.01"))
    order.status = "REFUNDED"
    db.session.commit()

    flash(
        f"Order #{order.id[:8]} refunded! Full pre-discount subtotal (${refund_amount:.2f}) credited to your balance "
        f"(you originally paid ${order.total_paid:.2f}).",
        "success",
    )
    return redirect(url_for("account.profile"))
