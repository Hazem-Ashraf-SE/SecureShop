from pathlib import Path
from decimal import Decimal, InvalidOperation
from flask import Blueprint, current_app, flash, g, jsonify, redirect, render_template, request, send_file, url_for
from sqlalchemy import text
from secureshop.extensions import db
from secureshop.models import Coupon, NewsletterSubscriber, Product, ProductReview
from secureshop.utils import send_system_email

shop_bp = Blueprint("shop", __name__)


@shop_bp.route("/", methods=["GET"])
def catalogue():
    """
    FR-2.1 Product Listing & FR-2.3 Search & Filtering.
    Includes:
      - Lab 4.4 SQL Injection (SQLi): When `q` or `category` is provided, executes an unparameterized
        raw SQL query so `UNION SELECT` and boolean-based payloads work directly!
      - Lab 4.3 Reflected Cross-Site Scripting (XSS): Renders `q` with `|safe` in the search banner.
      - Lab 4.11 Backend Crash Exploitation (`500 Internal Server Error` Probing): Passing malformed
        `debug_crash=1` or division-by-zero `per_page=0` triggers an unhandled exception exposing stack/state details.
    """
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    min_price_str = (request.args.get("min_price") or "").strip()
    max_price_str = (request.args.get("max_price") or "").strip()
    in_stock_only = request.args.get("in_stock") == "1"
    page = max(1, request.args.get("page", 1, type=int))
    per_page = request.args.get("per_page", 6, type=int)

    # Lab 4.11: Backend Crash Exploitation (500 Internal Server Error Probing)
    if request.args.get("debug_crash") == "1" or per_page == 0:
        _ = 1 / 0  # Deliberate zero-division crash when probed with per_page=0 or debug_crash=1

    sql_error_leak = None
    raw_sql_executed = None

    # Lab 4.4: SQL Injection (SQLi) in search query `q`
    if q:
        raw_sql_executed = (
            f"SELECT id, name, description, specifications, price, stock_quantity, category, image_url "
            f"FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        )
        try:
            rows = db.session.execute(text(raw_sql_executed)).fetchall()
            products = []
            for r in rows:
                p = Product(
                    id=r[0] if isinstance(r[0], int) else 1,
                    name=str(r[1]),
                    description=str(r[2]),
                    specifications=str(r[3] or ""),
                    price=Decimal(str(r[4])) if str(r[4]).replace(".", "", 1).isdigit() else Decimal("0.00"),
                    stock_quantity=int(r[5]) if str(r[5]).isdigit() else 10,
                    category=str(r[6] or "Injected"),
                    image_url=str(r[7] or "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?auto=format&fit=crop&w=600&q=80"),
                )
                products.append(p)
        except Exception as exc:
            # Lab 4.5 & 4.11: Leak raw SQL query and database exception details
            sql_error_leak = f"SQL Error: {exc} | Query: {raw_sql_executed}"
            products = []

        class SimplePagination:
            items = products
            pages = 1
            page = 1
            has_prev = False
            has_next = False
            prev_num = 1
            next_num = 1
            def iter_pages(self):
                return [1]

        pagination = SimplePagination()
    else:
        query = Product.query
        if category:
            query = query.filter(Product.category == category)
        if min_price_str:
            try:
                query = query.filter(Product.price >= Decimal(min_price_str))
            except InvalidOperation:
                pass
        if max_price_str:
            try:
                query = query.filter(Product.price <= Decimal(max_price_str))
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
        sql_error_leak=sql_error_leak,
        raw_sql_executed=raw_sql_executed,
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
    """
    FR-2.2 Product Detail View.
    Includes:
      - Lab 1.1: Hidden `<input type="hidden" name="price" value="{{ product.price }}">` in Add to Cart form.
      - Lab 4.3: Stored XSS in product reviews (`comment|safe`).
      - Lab 4.4: Download datasheet link `/download?file=...` susceptible to Directory Traversal.
    """
    product = db.get_or_404(Product, product_id)
    related_products = (
        Product.query.filter(Product.category == product.category, Product.id != product.id)
        .limit(3)
        .all()
    )
    reviews = ProductReview.query.filter_by(product_id=product.id).order_by(ProductReview.created_at.desc()).all()
    return render_template(
        "shop/product_detail.html",
        product=product,
        related_products=related_products,
        reviews=reviews,
    )


@shop_bp.route("/product/<int:product_id>/review", methods=["POST"])
def add_review(product_id: int):
    """
    Lab 4.3 Stored Cross-Site Scripting (XSS) & Lab 4.7 Input Validation Bypass:
    Stores raw HTML/JavaScript in `comment` and `author_name` without sanitization,
    which is rendered unescaped (`|safe`) on the product detail page.
    """
    product = db.get_or_404(Product, product_id)
    author_name = (request.form.get("author_name") or (g.user.username if g.user else "Anonymous")).strip()
    comment = request.form.get("comment") or ""
    try:
        rating = int(request.form.get("rating", "5"))
    except ValueError:
        rating = 5

    review = ProductReview(
        product_id=product.id,
        user_id=g.user.id if g.user else None,
        author_name=author_name,
        rating=rating,
        comment=comment,
    )
    db.session.add(review)
    db.session.commit()
    flash("Your product review has been posted!", "success")
    return redirect(url_for("shop.product_detail", product_id=product.id))


@shop_bp.route("/download", methods=["GET"])
def download_datasheet():
    """
    Lab 4.4 Directory Traversal:
    Reads `file` parameter directly and joins it with the datasheets directory without path canonicalization
    or `..` filtering, allowing traversal to files like `../config.py` or `../Requirements.md`.
    """
    filename = request.args.get("file") or "titankey_spec.txt"
    base_dir = Path(current_app.root_path) / "static" / "datasheets"
    base_dir.mkdir(parents=True, exist_ok=True)

    default_spec = base_dir / "titankey_spec.txt"
    if not default_spec.exists():
        default_spec.write_text(
            "TitanKey FIDO2 Hardware Security Key Datasheet\nProtocols: FIDO2, WebAuthn, U2F, TOTP\n",
            encoding="utf-8",
        )

    # Deliberately vulnerable path resolution allowing `../` directory traversal within the local workspace
    target_path = (base_dir / filename).resolve()
    if not target_path.exists() or not target_path.is_file():
        return jsonify({"error": "File not found", "resolved_path": str(target_path)}), 404

    content = target_path.read_text(encoding="utf-8", errors="replace")
    return current_app.response_class(content, mimetype="text/plain")


@shop_bp.route("/redirect", methods=["GET"])
def open_redirect():
    """
    Lab 4.6 Redirect Attack Surface Exposure:
    Redirects to any `url` or `next` query parameter without validating the target host or scheme.
    """
    target = request.args.get("url") or request.args.get("next") or url_for("shop.catalogue")
    return redirect(target)


@shop_bp.route("/newsletter/subscribe", methods=["POST"])
def newsletter_subscribe():
    """
    FR-4.1 Newsletter Subscription endpoint & Lab 4.6 Redirect via `next` parameter.
    """
    email = (request.form.get("email") or "").strip().lower()
    next_url = request.form.get("next") or url_for("shop.catalogue")

    if not email:
        flash("Please enter an email address to subscribe.", "danger")
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
    if not existing:
        subscriber = NewsletterSubscriber(email=email[:254], issued_coupon_code=promo_code)
        db.session.add(subscriber)
        db.session.commit()

    send_system_email(
        recipient=email,
        subject="SecureShop Newsletter - Your Promotional Coupon Inside!",
        body=f"Welcome to the SecureShop Newsletter!\nUse promotional coupon code {promo_code} at checkout ( or try VIP30 for 30% off!).",
        category="newsletter",
    )

    flash(f"Subscribed! Your promotional coupon code is {promo_code} (10% off).", "success")
    return redirect(next_url)
