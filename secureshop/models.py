import uuid
from datetime import datetime, timezone
from decimal import Decimal
import bcrypt
from werkzeug.security import check_password_hash
from secureshop.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    """Core Data Entity: User (FR-1, FR-6, FR-7 & Hardened Security Controls)."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")  # 'customer' | 'admin'
    store_credit = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("500.00"))
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    is_suspended = db.Column(db.Boolean, nullable=False, default=False)

    # FR-1.2 Single-use, time-bound verification token
    verification_token = db.Column(db.String(128), unique=True, nullable=True)
    verification_sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    pending_email = db.Column(db.String(254), nullable=True)

    # FR-1.3 & SR-6 Multi-Factor Authentication (6-digit OTP + TOTP + Replay & Brute-Force Protection)
    two_fa_enabled = db.Column(db.Boolean, nullable=False, default=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    current_otp_hash = db.Column(db.String(128), nullable=True)  # Stored hashed, never plaintext
    otp_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_used_totp_step = db.Column(db.Integer, nullable=True)  # Prevents TOTP replay within 30s window

    # Brute-Force & Lockout Tracking (SR-6 / Lab 1.5 / 4.8)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    login_locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    failed_otp_attempts = db.Column(db.Integer, nullable=False, default=0)
    otp_locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    # Behavioral Keystroke & Context-Aware Login Defense (Lab 4 & Lab 5)
    # Only aggregate timing statistics are stored; NEVER raw typed characters!
    keystroke_mean_ms = db.Column(db.Float, nullable=True)
    keystroke_std_ms = db.Column(db.Float, nullable=True)
    keystroke_sample_count = db.Column(db.Integer, nullable=False, default=0)
    allowed_region = db.Column(db.String(64), nullable=True, default="LOCAL")
    last_login_ip = db.Column(db.String(64), nullable=True)
    last_login_region = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    cart_items = db.relationship("CartItem", backref="user", lazy=True, cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy=True, order_by="Order.created_at.desc()")
    sessions = db.relationship("UserSession", backref="user", lazy=True, cascade="all, delete-orphan")
    passkeys = db.relationship("WebAuthnCredential", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """SR-7 / Lab 2.6: Salted, slow bcrypt hashing (cost factor 12)."""
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Verifies password using constant-time bcrypt check (with fallback for legacy hashes)."""
        if not self.password_hash:
            return False
        if self.password_hash.startswith(("$2a$", "$2b$", "$2y$")):
            try:
                return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
            except ValueError:
                return False
        return check_password_hash(self.password_hash, password)


class WebAuthnCredential(db.Model):
    """Lab 5 (2.12): Server-bound Ed25519 FIDO2/Passkey credential storage."""
    __tablename__ = "webauthn_credentials"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    public_key_pem = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class UserSession(db.Model):
    """FR-1.4 & SR-6: Server-side tracked session identifier."""
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent_hash = db.Column(db.String(64), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)


class SecurityAuditLog(db.Model):
    """Audit trail for Blue Team detection (ATO, Bot/Paste, Imposter, Region/Off-hours, RBAC)."""
    __tablename__ = "security_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, default="INFO")  # INFO | WARNING | HIGH | CRITICAL
    username = db.Column(db.String(64), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=False)  # Never stores passwords or raw keystrokes!
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


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
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class CartItem(db.Model):
    """Core Data Entity: Cart / CartItem (FR-3, SR-1)."""
    __tablename__ = "cart_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id", ondelete="CASCADE"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    product = db.relationship("Product", lazy="joined")

    @property
    def line_total(self) -> Decimal:
        """FR-3.3 & SR-1: Dynamic line-item total strictly from authoritative server-side product pricing."""
        if not self.product or self.quantity <= 0:
            return Decimal("0.00")
        return (Decimal(str(self.product.price)) * Decimal(self.quantity)).quantize(Decimal("0.01"))


class Coupon(db.Model):
    """Core Data Entity: Coupon (FR-4, FR-7.3, SR-2)."""
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
    """SR-2: Tracks coupon redemptions per user and order (prevents replay/alternating stacking)."""
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
    """Core Data Entity: Order (FR-5, FR-6.2, SR-5 State Machine)."""
    __tablename__ = "orders"

    id = db.Column(db.String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    # SR-5 Strict State Machine: PENDING_PAYMENT -> PAID -> CONFIRMED (or CANCELLED)
    status = db.Column(db.String(32), nullable=False, default="PENDING_PAYMENT")
    subtotal_amount = db.Column(db.Numeric(10, 2), nullable=False)
    discount_amount = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))
    total_paid = db.Column(db.Numeric(10, 2), nullable=False)
    applied_coupons = db.Column(db.Text, nullable=False, default="[]")  # JSON list of unique coupon codes
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


class EmailOutbox(db.Model):
    """Local dev/testing email outbox table so confirmation links & 2FA OTPs can be inspected offline."""
    __tablename__ = "email_outbox"

    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(254), nullable=False, index=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default="general")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
