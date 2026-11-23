from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Product
from secureshop.utils import calculate_cart_summary, log_security_event, login_required

cart_bp = Blueprint("cart", __name__, url_prefix="/cart")


@cart_bp.route("/", methods=["GET"])
@login_required
def view_cart():
    """FR-3.2, FR-3.3 & SR-1: Displays persistent user cart with authoritative server-side pricing."""
    summary = calculate_cart_summary(g.user)
    return render_template("cart/cart.html", summary=summary)


@cart_bp.route("/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id: int):
    """
    FR-3.1, SR-1, Lab 1.1, Lab 3.2, Lab 3.5, Lab 4.7:
    - Ignores any client-supplied `price`, `total`, or `discount` parameters (SR-1).
    - Strictly enforces `1 <= quantity <= MAX_CART_QUANTITY_PER_ITEM` (blocks negative quantities & 32-bit integer overflows).
    """
    product = db.get_or_404(Product, product_id)

    # Audit any client-side price tampering attempts
    if any(k in request.form for k in ("price", "unit_price", "total", "discount")):
        log_security_event(
            "PRICE_TAMPERING_BLOCKED",
            f"Ignored client-supplied pricing parameters on /cart/add/{product_id}",
            severity="HIGH",
            username=g.user.username,
        )

    raw_qty = (request.form.get("quantity") or "1").strip()
    try:
        quantity = int(raw_qty)
    except ValueError:
        flash("Quantity must be a valid positive integer.", "danger")
        return redirect(url_for("shop.product_detail", product_id=product.id)), 400

    max_qty = current_app.config.get("MAX_CART_QUANTITY_PER_ITEM", 99)
    if quantity <= 0 or quantity > max_qty:
        log_security_event(
            "INVALID_QUANTITY_BLOCKED",
            f"Rejected invalid cart quantity={raw_qty} for product_id={product_id}",
            severity="WARNING",
            username=g.user.username,
        )
        flash(f"Quantity must be a positive integer between 1 and {max_qty}.", "danger")
        return redirect(url_for("shop.product_detail", product_id=product.id)), 400

    if product.stock_quantity <= 0:
        flash(f"'{product.name}' is currently out of stock.", "warning")
        return redirect(url_for("shop.product_detail", product_id=product.id))

    cart_item = CartItem.query.filter_by(user_id=g.user.id, product_id=product.id).first()
    new_qty = (cart_item.quantity + quantity) if cart_item else quantity

    if new_qty > max_qty or new_qty > product.stock_quantity:
        cap = min(max_qty, product.stock_quantity)
        flash(
            f"Cannot add {quantity} unit(s). Maximum allowed for '{product.name}' is {cap} unit(s).",
            "warning",
        )
        return redirect(url_for("shop.product_detail", product_id=product.id)), 400

    if cart_item:
        cart_item.quantity = new_qty
    else:
        cart_item = CartItem(user_id=g.user.id, product_id=product.id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    flash(f"Added {quantity} x '{product.name}' to your shopping cart.", "success")
    return redirect(url_for("cart.view_cart"))


@cart_bp.route("/update/<int:item_id>", methods=["POST"])
@login_required
def update_cart_item(item_id: int):
    """
    FR-3.1, SR-1, Lab 3.2, Lab 3.5:
    - Enforces ownership (`user_id=g.user.id`), strict positive integer bounds (`1..MAX_CART_QUANTITY_PER_ITEM`),
      and ignores any client-supplied price parameters.
    """
    cart_item = CartItem.query.filter_by(id=item_id, user_id=g.user.id).first_or_404()

    if any(k in request.form for k in ("price", "unit_price", "total", "discount")):
        log_security_event(
            "PRICE_TAMPERING_BLOCKED",
            f"Ignored client-supplied pricing parameters on /cart/update/{item_id}",
            severity="HIGH",
            username=g.user.username,
        )

    raw_qty = (request.form.get("quantity") or "").strip()
    try:
        quantity = int(raw_qty)
    except ValueError:
        flash("Quantity must be a valid positive integer.", "danger")
        return redirect(url_for("cart.view_cart")), 400

    max_qty = current_app.config.get("MAX_CART_QUANTITY_PER_ITEM", 99)
    if quantity <= 0 or quantity > max_qty:
        flash(f"Quantity must be a positive integer between 1 and {max_qty}.", "danger")
        return redirect(url_for("cart.view_cart")), 400

    if cart_item.product and quantity > cart_item.product.stock_quantity:
        flash(
            f"Only {cart_item.product.stock_quantity} unit(s) of '{cart_item.product.name}' are available in stock.",
            "warning",
        )
        return redirect(url_for("cart.view_cart")), 400

    cart_item.quantity = quantity
    db.session.commit()
    flash(f"Updated '{cart_item.product.name}' quantity to {quantity}.", "success")
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
