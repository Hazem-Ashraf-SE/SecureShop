import traceback
from flask import Flask, g, jsonify, request, render_template
from config import Config
from secureshop.extensions import db
from secureshop.models import Coupon, KeystrokeTelemetryLog, Order, Product, User
from secureshop.seed import seed_initial_data
from secureshop.utils import load_logged_in_user


def create_app(config_class=Config) -> Flask:
    """Application Factory pattern (Phase 2 Controlled Vulnerability Lab Build)."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    # Register modular Blueprints (auth, shop, cart, checkout, account, admin)
    from secureshop.blueprints.auth import auth_bp
    from secureshop.blueprints.shop import shop_bp
    from secureshop.blueprints.cart import cart_bp
    from secureshop.blueprints.checkout import checkout_bp
    from secureshop.blueprints.account import account_bp
    from secureshop.blueprints.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(shop_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(checkout_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def before_request_hook():
        load_logged_in_user()

    @app.after_request
    def after_request_hook(response):
        # Lab 4.1 & 4.5: Man-in-the-Middle (MitM) Interception & Data Leaks in headers
        response.headers["X-Powered-By"] = "SecureShop-Lab/2.0 (Python-Flask; Debug-Telemetry-Enabled)"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    @app.context_processor
    def inject_globals():
        return {
            "current_user": getattr(g, "user", None),
            "cart_count": getattr(g, "cart_count", 0),
        }

    # DevOps readiness: container healthcheck endpoint
    @app.route("/healthz", methods=["GET"])
    def healthcheck():
        return jsonify({"status": "ok", "service": "secureshop"}), 200

    # ==========================================================================
    # Lab 4.5 & Lab 4.10: Directory Enumeration, Hidden Endpoint Reconnaissance,
    # and Data Leaks (Response Body Exposure)
    # ==========================================================================
    @app.route("/robots.txt", methods=["GET"])
    def robots_txt():
        content = (
            "User-agent: *\n"
            "Disallow: /admin-console-hidden\n"
            "Disallow: /backup\n"
            "Disallow: /api/debug/vars\n"
            "Disallow: /auth/telemetry-logs\n"
            "Disallow: /auth/encrypt-notification\n"
        )
        return app.response_class(content, mimetype="text/plain")

    @app.route("/backup", methods=["GET"])
    @app.route("/.git/config", methods=["GET"])
    def exposed_backup():
        """Lab 4.5 & 4.10: Unauthenticated backup dump leaking users, plaintext passwords, OTPs, and coupons."""
        users = User.query.all()
        coupons = Coupon.query.all()
        return jsonify({
            "backup_dump": "secureshop_pre_prod_snapshot",
            "users": [
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "role": u.role,
                    "plaintext_password": u.plaintext_password,
                    "password_hash": u.password_hash,
                    "store_credit": str(u.store_credit),
                    "totp_secret": u.totp_secret,
                    "current_otp_code": u.current_otp_code,
                    "passkey_credential_id": u.passkey_credential_id,
                }
                for u in users
            ],
            "secret_coupons": [
                {"code": c.code, "type": c.discount_type, "value": str(c.discount_value)}
                for c in coupons
            ],
        }), 200

    @app.route("/admin-console-hidden", methods=["GET", "POST"])
    def hidden_admin_console():
        """
        Lab 4.9 & 4.10: Directory Enumeration & Privilege Escalation via Unprotected Hidden Endpoint.
        Allows unauthenticated recon discovery and instant user role promotion or store credit injection.
        """
        if request.method == "POST":
            target_username = (request.form.get("username") or "").strip()
            new_role = (request.form.get("role") or "admin").strip()
            user = User.query.filter(db.func.lower(User.username) == target_username.lower()).first()
            if user:
                user.role = new_role
                db.session.commit()
                return jsonify({"status": "elevated", "username": user.username, "new_role": user.role}), 200
        users = User.query.all()
        return jsonify({
            "hidden_endpoint": "/admin-console-hidden",
            "note": "POST username & role=admin to elevate privileges (Lab 4.9 / 4.10)",
            "registered_users": [{"username": u.username, "role": u.role, "email": u.email} for u in users],
        }), 200

    @app.route("/api/debug/vars", methods=["GET"])
    def debug_vars():
        """Lab 4.5 & 4.11: Exposes internal configuration and crash trigger."""
        if request.args.get("crash") == "1":
            raise RuntimeError("Deliberate Backend Crash Exploitation triggered via /api/debug/vars?crash=1")
        return jsonify({
            "app_name": "SecureShop Vulnerable Lab",
            "secret_key_preview": app.config.get("SECRET_KEY"),
            "database_uri": app.config.get("SQLALCHEMY_DATABASE_URI"),
            "email_truncation_limit": 32,
            "endpoints": [str(rule) for rule in app.url_map.iter_rules()],
        }), 200

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        """
        Lab 4.11: Backend Crash Exploitation (`500 Internal Server Error` Probing).
        When an unhandled exception occurs (such as `/api/debug/vars?crash=1` or `/?per_page=0`),
        returns a 500 response containing the raw stack trace, exception class, and environment metadata.
        """
        from werkzeug.exceptions import HTTPException
        if isinstance(error, HTTPException):
            return error
        db.session.rollback()
        tb = traceback.format_exc()
        return jsonify({
            "error": "500 Internal Server Error (Lab 4.11 Backend Crash Exploitation)",
            "exception_type": type(error).__name__,
            "exception_message": str(error),
            "stack_trace": tb,
            "secret_key_leaked": app.config.get("SECRET_KEY"),
        }), 500

    with app.app_context():
        db.create_all()
        seed_initial_data()

    return app
