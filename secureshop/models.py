import uuid
from datetime import datetime, timezone
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash
from secureshop.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    """Core Data Entity: User (FR-1, FR-6, FR-7 & Phase 2 Lab Scenarios)."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # Lab 4 (2.6): Plaintext / Weak Password Storage column for classroom simulation
    plaintext_password = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(20), nullable=False, default="customer")  # 'customer' | 'admin'
    store_credit = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("500.00"))
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    is_suspended = db.Column(db.Boolean, nullable=False, default=False)

    # FR-1.2 Single-use, time-bound verification token
    verification_token = db.Column(db.String(128), unique=True, nullable=True)
    verification_sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    pending_email = db.Column(db.String(254), nullable=True)

    # FR-1.3 Multi-Factor Authentication (4-Digit OTP & TOTP secret)
    two_fa_enabled = db.Column(db.Boolean, nullable=False, default=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    current_otp_code = db.Column(db.String(16), nullable=True)
    otp_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Lab 4 & Lab 5: Behavioral Keystroke & Geolocation / Passkey attributes
    keystroke_profile_mean = db.Column(db.Float, nullable=True, default=120.0)
    allowed_region = db.Column(db.String(64), nullable=True, default="US-EAST")
    passkey_credential_id = db.Column(db.String(128), nullable=True)
    passkey_public_key = db.Column(db.String(256), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    cart_items = db.relationship("CartItem", backref="user", lazy=True, cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy=True, order_by="Order.created_at.desc()")
    sessions = db.relationship("UserSession", backref="user", lazy=True, cascade="all, delete-orphan")
    reviews = db.relationship("ProductReview", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)
        # Lab 4 (2.6): Store weak/plaintext representation alongside hash for lab inspection
        self.plaintext_password = password

    def check_password(self, password: str) -> bool:
        if self.plaintext_password and self.plaintext_password == password:
            return True
        return check_password_hash(self.password_hash, password)


class UserSession(db.Model):
    """FR-1.4 Server-side tracked session identifier."""
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class Product(db.Model):
    """Core Data Entity: Product (FR-2, FR-7.2)."""
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    specifications = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False, default=0)
    category = db.Column(db.String(80), nullable=False, index=True)
    image_url = db.Column(db.String(500), nullable=False)
    datasheet_filename = db.Column(db.String(120), nullable=True, default="titankey_spec.txt")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    reviews = db.relationship("ProductReview", backref="product", lazy=True, cascade="all, delete-orphan")


class ProductReview(db.Model):
    """Product reviews for Stored XSS & Client Input Validation labs."""
    __tablename__ = "product_reviews"

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    author_name = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False, default=5)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class CartItem(db.Model):
    """Core Data Entity: Cart / CartItem (FR-3 & Lab 1.1 Client-Side Price Control)."""
    __tablename__ = "cart_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    # Lab 1.1 / 3.1: Excessive Trust in Client-Side Controls (stores client-submitted unit_price)
    unit_price = db.Column(db.Numeric(10, 2), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    product = db.relationship("Product", lazy="joined")

    @property
    def effective_unit_price(self) -> Decimal:
        if self.unit_price is not None:
            return Decimal(str(self.unit_price)).quantize(Decimal("0.01"))
        if self.product:
            return Decimal(str(self.product.price)).quantize(Decimal("0.01"))
        return Decimal("0.00")

    @property
    def line_total(self) -> Decimal:
        """Calculates line-item total using client-supplied unit_price if present."""
        return (self.effective_unit_price * Decimal(self.quantity)).quantize(Decimal("0.01"))


class Coupon(db.Model):
    """Core Data Entity: Coupon (FR-4, FR-7.3)."""
    __tablename__ = "coupons"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    discount_type = db.Column(db.String(20), nullable=False)  # 'fixed' | 'percent'
    discount_value = db.Column(db.Numeric(10, 2), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    max_uses_per_user = db.Column(db.Integer, nullable=False, default=1)
    total_usage_limit = db.Column(db.Integer, nullable=True)
    times_used = db.Column(db.Integer, nullable=False, default=0)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class CouponUsage(db.Model):
    """Tracks coupon redemptions per user and order."""
    __tablename__ = "coupon_usages"

    id = db.Column(db.Integer, primary_key=True)
    coupon_id = db.Column(db.Integer, db.ForeignKey("coupons.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    order_id = db.Column(db.String(64), nullable=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    coupon = db.relationship("Coupon", backref="usages")


class NewsletterSubscriber(db.Model):
    """FR-4.1 Newsletter Subscription record."""
    __tablename__ = "newsletter_subscribers"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    issued_coupon_code = db.Column(db.String(64), nullable=False)
    subscribed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class Order(db.Model):
    """Core Data Entity: Order (FR-5, FR-6.2)."""
    __tablename__ = "orders"

    id = db.Column(db.String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default="PAID")  # 'PENDING' | 'PAID' | 'CANCELLED'
    subtotal_amount = db.Column(db.Numeric(10, 2), nullable=False)
    discount_amount = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))
    total_paid = db.Column(db.Numeric(10, 2), nullable=False)
    applied_coupons = db.Column(db.Text, nullable=False, default="[]")  # JSON list of coupon codes
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    items = db.relationship("OrderItem", backref="order", lazy="joined", cascade="all, delete-orphan")


class OrderItem(db.Model):
    """Core Data Entity: OrderItem line-item snapshot (FR-5.2, FR-5.3)."""
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(64), db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="SET NULL"), nullable=True)
    product_name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price_at_purchase = db.Column(db.Numeric(10, 2), nullable=False)

    @property
    def line_total(self) -> Decimal:
        return (Decimal(str(self.unit_price_at_purchase)) * Decimal(self.quantity)).quantize(Decimal("0.01"))


class KeystrokeTelemetryLog(db.Model):
    """Lab 4 (2.1 - 2.5): Stores behavioral keystroke telemetry & raw keystrokes."""
    __tablename__ = "keystroke_telemetry_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, index=True)
    raw_typed_characters = db.Column(db.Text, nullable=True)  # Lab 2.5: Sensitive Keystroke Data Exposure
    intervals_json = db.Column(db.Text, nullable=True)
    mean_interval_ms = db.Column(db.Float, nullable=True)
    is_pasted = db.Column(db.Boolean, nullable=False, default=False)
    classification = db.Column(db.String(64), nullable=False, default="normal")
    client_ip = db.Column(db.String(64), nullable=True)
    region = db.Column(db.String(64), nullable=True)
    gps_coords = db.Column(db.String(64), nullable=True)
    login_hour_utc = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class EmailOutbox(db.Model):
    """Local dev/testing email outbox table so confirmation links & 2FA OTPs can be inspected offline."""
    __tablename__ = "email_outbox"

    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(254), nullable=False, index=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default="general")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
