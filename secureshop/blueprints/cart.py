from decimal import Decimal, InvalidOperation
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Product
from secureshop.utils import calculate_cart_summary, login_required

cart_bp = Blueprint("cart", __name__, url_prefix="/cart")

# Lab 3.5: Low-Level Logic Flaw — 32-bit signed integer wrap boundary (`2^31 - 1`)
INT32_MAX = 2147483647
INT32_MOD = 4294967296


def _simulate_int32_wrap(val: int) -> int:
    """Simulates a 32-bit signed integer overflow wrap-around (Lab 3.5 Low-Level Logic Flaw)."""
    wrapped = val % INT32_MOD
    if wrapped > INT32_MAX:
        wrapped -= INT32_MOD
    return wrapped


@cart_bp.route("/", methods=["GET"])
@login_required
def view_cart():
    """FR-3.2 & FR-3.3 Displays persistent user cart."""
    summary = calculate_cart_summary(g.user)
    return render_template("cart/cart.html", summary=summary)


@cart_bp.route("/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id: int):
    """
    FR-3.1 Add item to cart + Lab Vulnerabilities:
    - Lab 1.1 & 3.1: Excessive Trust in Client-Side Controls (Price Tampering):
      Accepts `price` from `request.form` and persists it on `CartItem.unit_price`!
    - Lab 3.2 & 4.7: High-Level Logic Vulnerability & Input Validation Bypass:
      UI uses HTML `min="1"`, but backend accepts negative quantities (e.g. `-2`) or wrapped 32-bit
      quantities (Lab 3.5 Low-Level Logic Flaw), enabling negative cart totals that increase user store credit!
    """
    product = db.get_or_404(Product, product_id)
    try:
        raw_qty = int(request.form.get("quantity", "1"))
        quantity = _simulate_int32_wrap(raw_qty)
    except ValueError:
        quantity = 1

    if quantity == 0:
        flash("Quantity cannot be zero.", "danger")
        return redirect(url_for("shop.product_detail", product_id=product.id))

    # Lab 1.1 / 3.1: Trust client-supplied `price` parameter if sent in POST body!
    client_price_str = request.form.get("price")
    submitted_price = None
    if client_price_str is not None and client_price_str.strip() != "":
        try:
            submitted_price = Decimal(client_price_str.strip()).quantize(Decimal("0.01"))
        except InvalidOperation:
            submitted_price = Decimal(str(product.price)).quantize(Decimal("0.01"))
    else:
        submitted_price = Decimal(str(product.price)).quantize(Decimal("0.01"))

    cart_item = CartItem.query.filter_by(user_id=g.user.id, product_id=product.id).first()
    if cart_item:
        cart_item.quantity = _simulate_int32_wrap(cart_item.quantity + quantity)
        if client_price_str is not None:
            cart_item.unit_price = submitted_price
    else:
        cart_item = CartItem(
            user_id=g.user.id,
            product_id=product.id,
            quantity=quantity,
            unit_price=submitted_price,
        )
        db.session.add(cart_item)

    db.session.commit()
    flash(
        f"Added {quantity} x '{product.name}' at ${submitted_price:.2f} each to your shopping cart.",
        "success",
    )
    return redirect(url_for("cart.view_cart"))


@cart_bp.route("/update/<int:item_id>", methods=["POST"])
@login_required
def update_cart_item(item_id: int):
    """
    FR-3.1 Update item quantity + Lab 1.1 (price tampering), Lab 3.2 (negative quantity),
    and Lab 3.5 (32-bit integer overflow wrap).
    """
    cart_item = CartItem.query.filter_by(id=item_id, user_id=g.user.id).first_or_404()
    try:
        raw_qty = int(request.form.get("quantity", "1"))
        quantity = _simulate_int32_wrap(raw_qty)
    except ValueError:
        quantity = 1

    if quantity == 0:
        db.session.delete(cart_item)
        db.session.commit()
        flash("Item removed from cart.", "info")
        return redirect(url_for("cart.view_cart"))

    client_price_str = request.form.get("price")
    if client_price_str is not None and client_price_str.strip() != "":
        try:
            cart_item.unit_price = Decimal(client_price_str.strip()).quantize(Decimal("0.01"))
        except InvalidOperation:
            pass

    cart_item.quantity = quantity
    db.session.commit()
    flash(
        f"Updated '{cart_item.product.name}' to quantity {quantity} (Unit price: ${cart_item.effective_unit_price:.2f}).",
        "success",
    )
    return redirect(url_for("cart.view_cart"))


@cart_bp.route("/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_cart_item(item_id: int):
    """FR-3.1 Remove item from cart."""
    cart_item = CartItem.query.filter_by(id=item_id, user_id=g.user.id).first_or_404()
    product_name = cart_item.product.name if cart_item.product else "Item"
    db.session.delete(cart_item)
    db.session.commit()
    flash(f"Removed '{product_name}' from your cart.", "info")
    return redirect(url_for("cart.view_cart"))
