from flask import Flask, g, jsonify, render_template
from config import Config
from secureshop.extensions import db
from secureshop.seed import seed_initial_data
from secureshop.utils import load_logged_in_user


def create_app(config_class=Config) -> Flask:
    """Application Factory pattern (NFR-2 & DevOps/Container Ready)."""
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

    # NFR-1 Non-leaking error handlers (no raw stack traces or SQL errors exposed)
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    with app.app_context():
        db.create_all()
        seed_initial_data()

    return app
