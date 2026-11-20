<<<<<<< HEAD
# SecureShop — E-Commerce Platform (Task 1: Functional Requirements Build)

**SecureShop** is a modular e-commerce platform built with **Python 3.11+**, **Flask**, **SQLAlchemy**, **Jinja2**, and **Bootstrap 5** in accordance with [Requirements.md](Requirements.md) and [SystemComponents.md](SystemComponents.md).

---

## 1. Implemented Functional Requirements (FR-1 to FR-7)

- **FR-1: User Registration & Authentication**
  - **FR-1.1 Account Registration**: Unique username, email address (up to 254 chars), and password registration (`/auth/register`).
  - **FR-1.2 Account Confirmation**: Generates a single-use, time-bound verification link (`/auth/verify/<token>`) sent via SMTP and inspectable offline in the built-in **Mail Outbox** (`/auth/outbox`).
  - **FR-1.3 Standard & Multi-Factor Login**: Two-step authentication (`/auth/login` -> `/auth/verify-2fa`) supporting both emailed 6-digit one-time passcodes (OTP) and RFC 6238 TOTP Authenticator codes.
  - **FR-1.4 Session Management & Logout**: Issues cryptographically signed, server-side-tracked session tokens (`UserSession` table) and invalidates/destroys them upon logout (`/auth/logout`).
- **FR-2: Product Catalogue & Discovery**
  - **FR-2.1 Product Listing**: Paginated Bootstrap 5 catalogue grid showing title, thumbnail, category, price, and stock availability (`/`).
  - **FR-2.2 Product Detail View**: Dedicated product page displaying full descriptions, technical specifications, price, stock status, and "Add to Cart" (`/product/<id>`).
  - **FR-2.3 Search & Filtering**: Keyword search (title & description), category filter, min/max price range filter, and "In Stock Only" toggle.
- **FR-3: Shopping Cart Management**
  - **FR-3.1 Cart Operations**: Add items, update positive integer quantities, and remove items (`/cart/`).
  - **FR-3.2 Session Persistence**: Cart records are persisted server-side in the database bound to the authenticated user.
  - **FR-3.3 Dynamic Subtotal Calculation**: Line-item totals and cart subtotals are calculated dynamically from authoritative server-side product pricing.
- **FR-4: Coupons & Newsletter Subsystem**
  - **FR-4.1 Newsletter Subscription**: Footer signup endpoint (`/newsletter/subscribe`) records email addresses and issues promotional coupon `WELCOME10` (10% off).
  - **FR-4.2 Coupon Validation & Application**: Checkout coupon submission (`/checkout/apply-coupon`) verifies active status, expiration, and per-user/global usage limits before applying percentage or fixed discounts.
- **FR-5: Checkout & Order Processing**
  - **FR-5.1 Store-Credit Payment**: Validates `store_credit >= final_order_total` prior to completing checkout (`/checkout/process`).
  - **FR-5.2 Atomic Balance Deduction & Order Creation**: Atomically deducts store credit, decrements product inventory, clears the user's cart, records coupon redemptions, and generates a UUID order with immutable line-item price snapshots.
  - **FR-5.3 Order Confirmation & History**: Displays verified order receipts (`/checkout/confirmation/<order_id>`) and retains immutable order history records.
- **FR-6: User Account & Profile Management**
  - **FR-6.1 Profile Viewing & Editing**: Update permitted attributes (`display_name`, `email` with re-verification link, `password`) while keeping `role` and `store_credit` read-only (`/account/`).
  - **FR-6.2 Personal Order History**: Lists all past orders with order UUIDs, timestamps, line items, applied discounts, and total paid.
- **FR-7: Administrative Panel**
  - **FR-7.1 User Management**: View users, assign/revoke roles (`customer` / `admin`), adjust store credit balances, and suspend or delete accounts (`/admin/?tab=users`).
  - **FR-7.2 Product Management**: Full CRUD for products including pricing, descriptions, specifications, and stock quantities (`/admin/?tab=products`).
  - **FR-7.3 Coupon Management**: Create, configure (fixed/percent value, usage limits, expiration date), and activate/deactivate promotional coupons (`/admin/?tab=coupons`).

---

## 2. Pre-Seeded Demo Accounts & Coupons

| Role | Username | Password | Initial Store Credit |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPass123!` | `$2,500.00` |
| **Customer** | `alice` | `CustomerPass123!` | `$750.00` |

- **Pre-seeded Coupons**: `WELCOME10` (10% off), `SAVE25` ($25.00 fixed off), `VIP15` (15% off).
- **Offline Email & 2FA Testing**: Click the **Mail Outbox** tab in the top navigation bar (`/auth/outbox`) to view account activation links and 6-digit 2FA login codes without needing an external mail server.

---

## 3. Running the Application Locally

```bash
python run.py
```

The server listens on `http://127.0.0.1:5000` (configurable via `HOST`, `PORT`, `DATABASE_URL`, and `SECRET_KEY` environment variables in `.env.example` for upcoming Docker/DevOps containerization).
=======
# SecureShop
E-Commerce Website for Software Security Course
>>>>>>> 748dea15196e4cba699b23c77cf2fa115eab4ec7
