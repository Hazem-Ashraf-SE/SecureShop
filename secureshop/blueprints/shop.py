from decimal import Decimal, InvalidOperation
from flask import Blueprint, flash, redirect, render_template, request, url_for
from secureshop.extensions import db
from secureshop.models import Coupon, NewsletterSubscriber, Product
from secureshop.utils import send_system_email

shop_bp = Blueprint("shop", __name__)


@shop_bp.route("/", methods=["GET"])
def catalogue():
    """
    FR-2.1 Product Listing (paginated & structured catalogue)
    FR-2.3 Search & Filtering (keyword in name/description, category, price range, availability)
    """
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    min_price_str = (request.args.get("min_price") or "").strip()
    max_price_str = (request.args.get("max_price") or "").strip()
    in_stock_only = request.args.get("in_stock") == "1"
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 6

    query = Product.query

    if q:
        like_pattern = f"%{q}%"
        query = query.filter(
            (Product.name.ilike(like_pattern)) | (Product.description.ilike(like_pattern))
        )

    if category:
        query = query.filter(Product.category == category)

    if min_price_str:
        try:
            min_price = Decimal(min_price_str)
            query = query.filter(Product.price >= min_price)
        except InvalidOperation:
            pass

    if max_price_str:
        try:
            max_price = Decimal(max_price_str)
            query = query.filter(Product.price <= max_price)
        except InvalidOperation:
            pass

    if in_stock_only:
        query = query.filter(Product.stock_quantity > 0)

    pagination = query.order_by(Product.id.asc()).paginate(page=page, per_page=per_page, error_out=False)

    categories = [
        row[0]
        for row in db.session.query(Product.category).distinct().order_by(Product.category.asc()).all()
    ]

    return render_template(
        "shop/catalogue.html",
        products=pagination.items,
        pagination=pagination,
        categories=categories,
        filters={
            "q": q,
            "category": category,
            "min_price": min_price_str,
            "max_price": max_price_str,
            "in_stock": in_stock_only,
        },
    )


@shop_bp.route("/product/<int:product_id>", methods=["GET"])
def product_detail(product_id: int):
    """FR-2.2 Product Detail View with full descriptions, specifications, price, stock, and Add to Cart."""
    product = db.get_or_404(Product, product_id)
    related_products = (
        Product.query.filter(Product.category == product.category, Product.id != product.id)
        .limit(3)
        .all()
    )
    return render_template("shop/product_detail.html", product=product, related_products=related_products)


@shop_bp.route("/newsletter/subscribe", methods=["POST"])
def newsletter_subscribe():
    """FR-4.1 Newsletter Subscription endpoint that records a valid email and issues a promotional coupon code."""
    email = (request.form.get("email") or "").strip().lower()
    next_url = request.form.get("next") or url_for("shop.catalogue")

    if not email or "@" not in email or len(email) > 254:
        flash("Please enter a valid email address (max 254 characters) to subscribe.", "danger")
        return redirect(next_url)

    promo_code = "WELCOME10"
    promo_coupon = Coupon.query.filter(db.func.upper(Coupon.code) == promo_code).first()
    if not promo_coupon:
        promo_coupon = Coupon(
            code=promo_code,
            discount_type="percent",
            discount_value=Decimal("10.00"),
            is_active=True,
            max_uses_per_user=1,
            description="10% off welcome newsletter promotional coupon",
        )
        db.session.add(promo_coupon)
        db.session.commit()

    existing = NewsletterSubscriber.query.filter(db.func.lower(NewsletterSubscriber.email) == email).first()
    if existing:
        flash(
            f"You are already subscribed to the newsletter! Your promotional coupon code is: {existing.issued_coupon_code}",
            "info",
        )
        return redirect(next_url)

    subscriber = NewsletterSubscriber(email=email, issued_coupon_code=promo_code)
    db.session.add(subscriber)
    db.session.commit()

    send_system_email(
        recipient=email,
        subject="SecureShop Newsletter - Your Promotional Coupon Inside!",
        body=(
            f"Welcome to the SecureShop Newsletter!\n\n"
            f"Use promotional coupon code {promo_code} at checkout to enjoy 10% off your order."
        ),
        category="newsletter",
    )

    flash(
        f"Thank you for subscribing! Your promotional coupon code is {promo_code} (10% off). "
        f"A confirmation copy was also delivered to the Mail Outbox.",
        "success",
    )
    return redirect(next_url)
