from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import Coupon, Order, Product, User
from secureshop.utils import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/", methods=["GET"])
@admin_required
def dashboard():
    """
    FR-7 Administrative Panel overview:
    - FR-7.1 User Management
    - FR-7.2 Product Management
    - FR-7.3 Coupon Management
    """
    tab = request.args.get("tab", "users")
    users = User.query.order_by(User.id.asc()).all()
    products = Product.query.order_by(Product.id.asc()).all()
    coupons = Coupon.query.order_by(Coupon.id.desc()).all()
    orders = Order.query.order_by(Order.created_at.desc()).limit(20).all()

    return render_template(
        "admin/dashboard.html",
        active_tab=tab,
        users=users,
        products=products,
        coupons=coupons,
        orders=orders,
    )


# ==============================================================================
# FR-7.1 User Management (assign/revoke roles, adjust store credit, suspend/delete)
# ==============================================================================
@admin_bp.route("/users/<int:user_id>/update", methods=["POST"])
@admin_required
def update_user(user_id: int):
    user = db.get_or_404(User, user_id)
    role = (request.form.get("role") or "customer").strip().lower()
    credit_str = (request.form.get("store_credit") or "0.00").strip()
    is_verified = request.form.get("is_verified") == "1"
    is_suspended = request.form.get("is_suspended") == "1"

    if role not in ("customer", "admin"):
        flash("Invalid role specified.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    if user.id == g.user.id and (role != "admin" or is_suspended):
        flash("You cannot revoke your own admin role or suspend your own active account.", "warning")
        return redirect(url_for("admin.dashboard", tab="users"))

    try:
        new_credit = Decimal(credit_str).quantize(Decimal("0.01"))
        if new_credit < Decimal("0.00"):
            raise InvalidOperation()
    except InvalidOperation:
        flash("Store credit must be a valid non-negative decimal amount.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    user.role = role
    user.store_credit = new_credit
    user.is_verified = is_verified
    user.is_suspended = is_suspended
    db.session.commit()

    flash(f"Updated user '{user.username}' (Role: {user.role}, Balance: ${user.store_credit:.2f}).", "success")
    return redirect(url_for("admin.dashboard", tab="users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id: int):
    user = db.get_or_404(User, user_id)
    if user.id == g.user.id:
        flash("You cannot delete your own administrator account.", "danger")
        return redirect(url_for("admin.dashboard", tab="users"))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user account '{username}'.", "info")
    return redirect(url_for("admin.dashboard", tab="users"))


# ==============================================================================
# FR-7.2 Product Management (CRUD products, pricing, descriptions, stock)
# ==============================================================================
@admin_bp.route("/products/create", methods=["POST"])
@admin_required
def create_product():
    name = (request.form.get("name") or "").strip()
    category = (request.form.get("category") or "General").strip()
    description = (request.form.get("description") or "").strip()
    specifications = (request.form.get("specifications") or "").strip()
    price_str = (request.form.get("price") or "0").strip()
    stock_str = (request.form.get("stock_quantity") or "0").strip()
    image_url = (request.form.get("image_url") or "").strip()

    if not name or not description:
        flash("Product name and description are required.", "danger")
        return redirect(url_for("admin.dashboard", tab="products"))

    try:
        price = Decimal(price_str).quantize(Decimal("0.01"))
        stock = int(stock_str)
        if price < Decimal("0.00") or stock < 0:
            raise ValueError()
    except (InvalidOperation, ValueError):
        flash("Price must be a valid non-negative decimal and stock must be a non-negative integer.", "danger")
        return redirect(url_for("admin.dashboard", tab="products"))

    if not image_url:
        image_url = "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=600&q=80"

    product = Product(
        name=name,
        category=category,
        description=description,
        specifications=specifications or "Standard Hardware / Software Security Certified",
        price=price,
        stock_quantity=stock,
        image_url=image_url,
    )
    db.session.add(product)
    db.session.commit()
    flash(f"Created product '{product.name}' at ${product.price:.2f}.", "success")
    return redirect(url_for("admin.dashboard", tab="products"))


@admin_bp.route("/products/<int:product_id>/update", methods=["POST"])
@admin_required
def update_product(product_id: int):
    product = db.get_or_404(Product, product_id)
    name = (request.form.get("name") or "").strip()
    category = (request.form.get("category") or "General").strip()
    description = (request.form.get("description") or "").strip()
    specifications = (request.form.get("specifications") or "").strip()
    price_str = (request.form.get("price") or "0").strip()
    stock_str = (request.form.get("stock_quantity") or "0").strip()
    image_url = (request.form.get("image_url") or "").strip()

    if not name or not description:
        flash("Product name and description cannot be empty.", "danger")
        return redirect(url_for("admin.dashboard", tab="products"))

    try:
        price = Decimal(price_str).quantize(Decimal("0.01"))
        stock = int(stock_str)
        if price < Decimal("0.00") or stock < 0:
            raise ValueError()
    except (InvalidOperation, ValueError):
        flash("Invalid price or stock quantity value.", "danger")
        return redirect(url_for("admin.dashboard", tab="products"))

    product.name = name
    product.category = category
    product.description = description
    product.specifications = specifications
    product.price = price
    product.stock_quantity = stock
    if image_url:
        product.image_url = image_url

    db.session.commit()
    flash(f"Updated product '{product.name}'.", "success")
    return redirect(url_for("admin.dashboard", tab="products"))


@admin_bp.route("/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def delete_product(product_id: int):
    product = db.get_or_404(Product, product_id)
    name = product.name
    db.session.delete(product)
    db.session.commit()
    flash(f"Deleted product '{name}'.", "info")
    return redirect(url_for("admin.dashboard", tab="products"))


# ==============================================================================
# FR-7.3 Coupon Management (create, configure discount/limits/expiration, deactivate)
# ==============================================================================
@admin_bp.route("/coupons/create", methods=["POST"])
@admin_required
def create_coupon():
    code = (request.form.get("code") or "").strip().upper()
    discount_type = (request.form.get("discount_type") or "fixed").strip().lower()
    discount_value_str = (request.form.get("discount_value") or "0").strip()
    max_uses_str = (request.form.get("max_uses_per_user") or "1").strip()
    total_limit_str = (request.form.get("total_usage_limit") or "").strip()
    expires_at_str = (request.form.get("expires_at") or "").strip()
    description = (request.form.get("description") or "").strip()

    if not code:
        flash("Coupon code is required.", "danger")
        return redirect(url_for("admin.dashboard", tab="coupons"))

    if discount_type not in ("fixed", "percent"):
        flash("Discount type must be 'fixed' or 'percent'.", "danger")
        return redirect(url_for("admin.dashboard", tab="coupons"))

    if Coupon.query.filter(db.func.upper(Coupon.code) == code).first():
        flash(f"Coupon code '{code}' already exists.", "danger")
        return redirect(url_for("admin.dashboard", tab="coupons"))

    try:
        discount_value = Decimal(discount_value_str).quantize(Decimal("0.01"))
        max_uses_per_user = int(max_uses_str)
        if discount_value <= Decimal("0.00") or max_uses_per_user <= 0:
            raise ValueError()
        if discount_type == "percent" and discount_value > Decimal("100.00"):
            flash("Percentage discount cannot exceed 100%.", "danger")
            return redirect(url_for("admin.dashboard", tab="coupons"))
        total_limit = int(total_limit_str) if total_limit_str else None
    except (InvalidOperation, ValueError):
        flash("Please provide valid positive numbers for discount value and usage limits.", "danger")
        return redirect(url_for("admin.dashboard", tab="coupons"))

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            flash("Invalid expiration date format (expected YYYY-MM-DD).", "danger")
            return redirect(url_for("admin.dashboard", tab="coupons"))

    coupon = Coupon(
        code=code,
        discount_type=discount_type,
        discount_value=discount_value,
        is_active=True,
        max_uses_per_user=max_uses_per_user,
        total_usage_limit=total_limit,
        expires_at=expires_at,
        description=description,
    )
    db.session.add(coupon)
    db.session.commit()
    flash(f"Created coupon '{coupon.code}'.", "success")
    return redirect(url_for("admin.dashboard", tab="coupons"))


@admin_bp.route("/coupons/<int:coupon_id>/toggle", methods=["POST"])
@admin_required
def toggle_coupon(coupon_id: int):
    coupon = db.get_or_404(Coupon, coupon_id)
    coupon.is_active = not coupon.is_active
    db.session.commit()
    state = "activated" if coupon.is_active else "deactivated"
    flash(f"Coupon '{coupon.code}' has been {state}.", "info")
    return redirect(url_for("admin.dashboard", tab="coupons"))


@admin_bp.route("/coupons/<int:coupon_id>/delete", methods=["POST"])
@admin_required
def delete_coupon(coupon_id: int):
    coupon = db.get_or_404(Coupon, coupon_id)
    code = coupon.code
    db.session.delete(coupon)
    db.session.commit()
    flash(f"Deleted coupon '{code}'.", "info")
    return redirect(url_for("admin.dashboard", tab="coupons"))
