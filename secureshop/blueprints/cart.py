from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import CartItem, Product
from secureshop.utils import calculate_cart_summary, login_required

cart_bp = Blueprint("cart", __name__, url_prefix="/cart")


@cart_bp.route("/", methods=["GET"])
@login_required
def view_cart():
    """FR-3.2 & FR-3.3 Displays persistent user cart with dynamic authoritative server-side subtotals."""
    summary = calculate_cart_summary(g.user)
    return render_template("cart/cart.html", summary=summary)


@cart_bp.route("/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id: int):
    """FR-3.1 Add item to cart (positive integers only)."""
    product = db.get_or_404(Product, product_id)
    try:
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        quantity = -1

    if quantity <= 0:
        flash("Quantity must be a positive integer.", "danger")
        return redirect(url_for("shop.product_detail", product_id=product.id))

    if product.stock_quantity <= 0:
        flash(f"'{product.name}' is currently out of stock.", "warning")
        return redirect(url_for("shop.product_detail", product_id=product.id))

    cart_item = CartItem.query.filter_by(user_id=g.user.id, product_id=product.id).first()
    new_qty = (cart_item.quantity + quantity) if cart_item else quantity

    if new_qty > product.stock_quantity:
        flash(
            f"Cannot add {quantity} unit(s). Only {product.stock_quantity} unit(s) of '{product.name}' available in stock.",
            "warning",
        )
        return redirect(url_for("shop.product_detail", product_id=product.id))

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
    """FR-3.1 Update item quantity (positive integers only)."""
    cart_item = CartItem.query.filter_by(id=item_id, user_id=g.user.id).first_or_404()
    try:
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        quantity = -1

    if quantity <= 0:
        flash("Quantity must be a positive integer (1 or greater). Use Remove to delete an item.", "danger")
        return redirect(url_for("cart.view_cart"))

    if cart_item.product and quantity > cart_item.product.stock_quantity:
        flash(
            f"Only {cart_item.product.stock_quantity} unit(s) of '{cart_item.product.name}' are available in stock.",
            "warning",
        )
        return redirect(url_for("cart.view_cart"))

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
