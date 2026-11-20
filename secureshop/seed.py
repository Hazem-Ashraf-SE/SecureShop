from decimal import Decimal
from secureshop.extensions import db
from secureshop.models import Coupon, Product, User
from secureshop.utils import generate_totp_secret


def seed_initial_data() -> None:
    """Seeds default users, product catalogue, and promotional coupons if database is empty."""
    if User.query.first() is None:
        admin = User(
            username="admin",
            email="admin@secureshop.local",
            display_name="System Administrator",
            role="admin",
            store_credit=Decimal("2500.00"),
            is_verified=True,
            two_fa_enabled=True,
            totp_secret=generate_totp_secret(),
        )
        admin.set_password("AdminPass123!")

        alice = User(
            username="alice",
            email="alice@secureshop.local",
            display_name="Alice Customer",
            role="customer",
            store_credit=Decimal("750.00"),
            is_verified=True,
            two_fa_enabled=True,
            totp_secret=generate_totp_secret(),
        )
        alice.set_password("CustomerPass123!")

        db.session.add_all([admin, alice])
        db.session.commit()

    if Product.query.first() is None:
        sample_products = [
            Product(
                name="TitanKey FIDO2 Hardware Security Key",
                category="Hardware Security",
                description=(
                    "Phishing-resistant FIDO2/WebAuthn & TOTP hardware authentication security key "
                    "with USB-C and NFC tap support for enterprise multi-factor protection."
                ),
                specifications="Protocols: FIDO2, WebAuthn, U2F, OATH-TOTP | Interface: USB-C & NFC | Crypto: Ed25519 & ECC P-256",
                price=Decimal("55.00"),
                stock_quantity=40,
                image_url="https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="Encrypted NVMe Hardware Vault 1TB",
                category="Storage & Encryption",
                description=(
                    "Portable hardware-encrypted NVMe solid-state drive featuring an onboard keypad "
                    "and real-time AES-256-XTS full-disk encryption."
                ),
                specifications="Capacity: 1TB NVMe | Encryption: FIPS 140-3 Level 3 AES-256-XTS | Interface: USB 3.2 Gen 2 (10Gbps)",
                price=Decimal("189.00"),
                stock_quantity=18,
                image_url="https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="NetGuard Pro Zero-Trust Firewall Appliance",
                category="Network Appliances",
                description=(
                    "Compact desktop gateway appliance equipped with deep packet inspection, "
                    "WireGuard VPN acceleration, and automated intrusion prevention."
                ),
                specifications="Ports: 4x 2.5GbE Intel NIC | Throughput: 2.3 Gbps IDS/IPS | RAM: 8GB ECC | Storage: 128GB eMMC",
                price=Decimal("299.00"),
                stock_quantity=12,
                image_url="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="Faraday Shielded Signal-Blocking Pouch",
                category="Privacy Gear",
                description=(
                    "Dual-layer silver/copper RF shielding sleeve engineered to block Cellular, Wi-Fi, "
                    "Bluetooth, GPS, RFID, and NFC signals completely."
                ),
                specifications="Attenuation: >85 dB (400MHz - 40GHz) | Dimensions: 21cm x 12cm | Material: Ballistic Nylon + Nickel/Copper mesh",
                price=Decimal("34.50"),
                stock_quantity=65,
                image_url="https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="AppSec & Penetration Testing Field Guide",
                category="Books & Training",
                description=(
                    "Comprehensive practical manual covering OWASP Top 10 vulnerabilities, "
                    "secure SDLC architecture, threat modeling, and defensive code review."
                ),
                specifications="Pages: 580 Hardcover | Edition: 2026 Revised | Topics: WebAuthn, ACID Transactions, RBAC, Injection Defense",
                price=Decimal("48.00"),
                stock_quantity=30,
                image_url="https://images.unsplash.com/photo-1532012197267-da84d127e765?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="SmartCard Air-Gapped Cold Wallet",
                category="Hardware Security",
                description=(
                    "EAL6+ certified secure element smartcard for air-gapped cryptographic key signing "
                    "and offline secret backup."
                ),
                specifications="Secure Element: CC EAL6+ | Connectivity: Air-Gapped QR & NFC | Battery: Passive / Battery-free",
                price=Decimal("79.99"),
                stock_quantity=25,
                image_url="https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=600&q=80",
            ),
            Product(
                name="USB Data Blocker & Power-Only Defender (3-Pack)",
                category="Privacy Gear",
                description=(
                    "Physically removes D+/D- data pins to prevent juice-jacking attacks when charging "
                    "devices at public USB kiosks and airports."
                ),
                specifications="Max Power: 240W USB-PD Pass-through | Data Pins: Physically Disconnected | Pack Size: 3 Adapters",
                price=Decimal("22.00"),
                stock_quantity=0,  # Out-of-stock item to demonstrate FR-2.3 availability filter
                image_url="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=600&q=80",
            ),
        ]
        db.session.add_all(sample_products)
        db.session.commit()

    if Coupon.query.first() is None:
        sample_coupons = [
            Coupon(
                code="WELCOME10",
                discount_type="percent",
                discount_value=Decimal("10.00"),
                is_active=True,
                max_uses_per_user=1,
                total_usage_limit=500,
                description="10% off promotional newsletter welcome discount",
            ),
            Coupon(
                code="SAVE25",
                discount_type="fixed",
                discount_value=Decimal("25.00"),
                is_active=True,
                max_uses_per_user=1,
                total_usage_limit=100,
                description="$25.00 fixed discount on security hardware",
            ),
            Coupon(
                code="VIP15",
                discount_type="percent",
                discount_value=Decimal("15.00"),
                is_active=True,
                max_uses_per_user=2,
                total_usage_limit=50,
                description="15% off VIP member discount",
            ),
        ]
        db.session.add_all(sample_coupons)
        db.session.commit()
