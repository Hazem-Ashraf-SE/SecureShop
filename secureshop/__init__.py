from flask import Flask, abort, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from config import Config
from secureshop.extensions import db
from secureshop.seed import seed_initial_data
from secureshop.utils import (
    check_rate_limit,
    get_csrf_token,
    load_logged_in_user,
    log_security_event,
    validate_csrf_token,
)


def create_app(config_class=Config) -> Flask:
    """Application Factory pattern hardened for Security Requirements (SR-1 through SR-8)."""
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
    def before_request_security_guard():
        # 1. Global IP rate limiting (Lab 4.8 Automated Fuzzing & Brute-Force Defense)
        if not app.config.get("TESTING", False) or app.config.get("ENFORCE_RATE_LIMIT_IN_TESTS", False):
            limit = app.config.get("GLOBAL_RATE_LIMIT_PER_MIN", 120)
            if not check_rate_limit("global", max_requests=limit, window_seconds=60):
                log_security_event("GLOBAL_RATE_LIMIT", f"Global rate limit exceeded on {request.path}", severity="WARNING")
                abort(429)

        # 2. Load authenticated user strictly from server-side session token (SR-6)
        load_logged_in_user()

        # 3. SR-8 Global Anti-CSRF validation on all state-changing HTTP methods
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Allow JSON WebAuthn challenge/verify API to also validate CSRF header when enabled
            if app.config.get("WTF_CSRF_ENABLED", True):
                if not validate_csrf_token():
                    log_security_event(
                        "CSRF_REJECTED",
                        f"Missing or invalid CSRF token on {request.method} {request.path}",
                        severity="HIGH",
                        username=g.user.username if g.user else None,
                    )
                    abort(400)

    @app.after_request
    def apply_security_headers(response):
        """
        Hardened HTTP Security Headers (Lab 4.1 MitM, Lab 4.2 XSS, Lab 4.5 Data Leaks):
        - Strict Content-Security-Policy (blocks inline script injection)
        - X-Content-Type-Options: nosniff
        - X-Frame-Options: DENY (anti-clickjacking / phishing overlay defense)
        - Referrer-Policy: strict-origin-when-cross-origin
        - Strict-Transport-Security (HSTS)
        - Cache-Control: no-store on sensitive authenticated pages
        - Removes verbose server banners
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' https://images.unsplash.com data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        if request.path.startswith(("/auth", "/account", "/admin", "/checkout")):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response

    @app.context_processor
    def inject_globals():
        return {
            "current_user": getattr(g, "user", None),
            "cart_count": getattr(g, "cart_count", 0),
            "csrf_token": get_csrf_token,
        }

    # DevOps readiness: container healthcheck endpoint (non-leaking)
    @app.route("/healthz", methods=["GET"])
    def healthcheck():
        return jsonify({"status": "ok"}), 200

    # Lab 4.10: Minimal non-leaking robots.txt (never lists sensitive internal paths)
    @app.route("/robots.txt", methods=["GET"])
    def robots_txt():
        return app.response_class("User-agent: *\nAllow: /\n", mimetype="text/plain")

    # NFR-1 & Lab 4.5 / 4.11: Non-leaking error handlers (zero stack traces, SQL errors, or internal paths)
    @app.errorhandler(400)
    def bad_request_error(error):
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def rate_limit_error(error):
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        if isinstance(error, HTTPException):
            return error
        db.session.rollback()
        log_security_event("UNHANDLED_EXCEPTION", f"Handled server error on {request.path}", severity="ERROR")
        return render_template("errors/500.html"), 500

    with app.app_context():
        db.create_all()
        seed_initial_data()

    return app
