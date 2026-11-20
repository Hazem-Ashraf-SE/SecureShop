Below is the complete **Software Requirements Specification (SRS)** for **SecureShop** corresponding to Phase 1 of the SDLC (Requirements Analysis), covering Functional Requirements, Security Requirements, Non-Functional Requirements, and Data/System Constraints.

---

### 1. Functional Requirements (FR)

**FR-1: User Registration & Authentication**

* **FR-1.1 Account Registration:** The system shall allow new users to register with a unique username, email address, and password.
* **FR-1.2 Account Confirmation:** The system shall generate a single-use, time-bound verification token/link sent to the user's email address to activate the account before allowing login.
* **FR-1.3 Standard & Multi-Factor Login:** The system shall authenticate users via username/email and password, followed by a second authentication factor (e.g., 2FA OTP, TOTP, or WebAuthn/Passkey challenge).
* **FR-1.4 Session Management & Logout:** The system shall issue a cryptographically signed, server-side-tracked session identifier upon authentication and invalidate/destroy the session upon logout.

**FR-2: Product Catalogue & Discovery**

* **FR-2.1 Product Listing:** The system shall display a paginated or structured catalogue of available products showing title, thumbnail image, price, and stock availability.
* **FR-2.2 Product Detail View:** The system shall provide a dedicated view for each product displaying full descriptions, specifications, current price, stock status, and an "Add to Cart" action.
* **FR-2.3 Search & Filtering:** The system shall allow users to query products by keyword (name/description) and filter results by category, price range, or availability.

**FR-3: Shopping Cart Management**

* **FR-3.1 Cart Operations:** Authenticated users shall be able to add items to their cart, update item quantities (positive integers only), and remove items.
* **FR-3.2 Session Persistence:** The system shall persist cart contents across page navigation and requests within an active user session (stored server-side or bound to the authenticated user's database record).
* **FR-3.3 Dynamic Subtotal Calculation:** The system shall dynamically calculate line-item totals and overall cart subtotals based on authoritative server-side product pricing.

**FR-4: Coupons & Newsletter Subsystem**

* **FR-4.1 Newsletter Subscription:** The system shall provide a newsletter signup endpoint that records a valid email address and issues a promotional coupon code.
* **FR-4.2 Coupon Validation & Application:** The system shall allow users to submit a coupon code during checkout, verify its validity and eligibility, and apply the corresponding fixed or percentage discount to the order total.

**FR-5: Checkout & Order Processing**

* **FR-5.1 Store-Credit Payment:** The system shall allow users to pay for their cart using their internal account store-credit balance, verifying that `store_credit >= final_order_total` prior to finalizing the transaction.
* **FR-5.2 Atomic Balance Deduction & Order Creation:** Upon successful checkout, the system shall atomically deduct the final total from the user's store credit, decrement product inventory, clear the active cart, and generate a unique order record.
* **FR-5.3 Order Confirmation & History:** The system shall display an order confirmation summary only after verified payment completion and retain immutable order history records per user.

**FR-6: User Account & Profile Management**

* **FR-6.1 Profile Viewing & Editing:** Authenticated users shall be able to view and update their permitted profile attributes (e.g., display name, email with re-verification, password) while preventing modification of restricted fields (e.g., role, store credit).
* **FR-6.2 Personal Order History:** Authenticated users shall be able to view a list of their past orders, including order IDs, timestamps, purchased items, applied discounts, and total paid.

**FR-7: Administrative Panel**

* **FR-7.1 User Management:** Administrators shall be able to view registered users, assign/revoke roles, adjust store credit if required, and suspend or delete accounts.
* **FR-7.2 Product Management:** Administrators shall be able to create, read, update, and delete (CRUD) products, including pricing, descriptions, and stock quantities.
* **FR-7.3 Coupon Management:** Administrators shall be able to create, configure (discount value/type, usage limits, expiration), and deactivate promotional coupon codes.

---

### 2. Security Requirements (SR)

* **SR-1 Server-Side Price & Quantity Integrity:** The backend shall ignore any client-supplied price or total parameters (`price`, `total`, `discount`) in HTTP requests and compute all pricing strictly from the server-side product database.
* **SR-2 Strict Business Rule Enforcement on Coupons:** The system shall store a list/set of all applied coupon codes per order, enforce single-use per coupon per user/order (blocking alternating coupon replay), and enforce a hard cap on maximum cumulative discounts (preventing negative totals).
* **SR-3 Consistent Input Length & Format Validation:** The system shall validate maximum field lengths (e.g., RFC-compliant email length <= 254 characters) at the API/controller boundary *before* any email dispatch or database persistence, rejecting over-long inputs with a `400 Bad Request` rather than silently truncating them.
* **SR-4 Explicit Role-Based Access Control (RBAC):** Access to `/admin` and privileged endpoints shall be enforced server-side via explicit user role attributes (`role == 'admin'`), never derived from email domain substrings or hidden URL obscurity.
* **SR-5 Server-Side Workflow State Machine:** Checkout and order fulfillment shall follow a strict server-side state machine (`CART -> PENDING_PAYMENT -> PAID -> CONFIRMED`). Direct requests to `/order-confirmation` without a valid, session-bound, `PAID` order ID shall be rejected.
* **SR-6 Server-Side 2FA Identity Binding & Rate Limiting:** During multi-factor authentication, the pending user identity shall be stored exclusively in a tamper-proof server-side session (never in a plaintext client cookie like `verify=username`), and OTP verification endpoints shall enforce strict attempt limits and lockout/cooldown timers to prevent brute-force attacks.
* **SR-7 Password Hashing & Credential Protection:** User passwords shall never be stored in plaintext; the system shall store salted, slow cryptographic hashes (e.g., Argon2id or bcrypt).
* **SR-8 Injection & Cross-Site Attack Defenses:** All database queries shall use parameterized statements/ORM bindings (preventing SQL Injection), all user-controlled outputs shall be contextually HTML-escaped (preventing XSS), and state-changing requests shall validate anti-CSRF tokens and `SameSite` cookie attributes.



---

### 3. Non-Functional Requirements (NFR)

* **NFR-1 Usability & Responsiveness:** The user interface shall provide clear navigation across all traditional tabs (Home/Catalogue, Cart, Checkout, Account, Login/Register, Admin), display clear and non-leaking error messages (no raw stack traces or SQL errors), and render responsively on both desktop and mobile viewports.
* **NFR-2 Maintainability & Architecture:** The codebase shall follow a modular separation of concerns (e.g., MVC or layered Controller–Service–Repository architecture) with inline documentation and a reproducible setup guide (`README.md`).
* **NFR-3 Auditability & Traceability:** Every security control implemented in the codebase shall map directly to a unique row in the project's **Security Coverage Matrix** (linking Threat Scenario → Root Cause → Code File/Line → Verification Evidence).
* **NFR-4 Data Integrity & Concurrency:** Checkout and store-credit transactions shall execute within database transactions (ACID compliance) to prevent race conditions or double-spending of store credit.



---

### 4. Core Data Entities (Logical Data Requirements)

* **User:** `id`, `username`, `email` (unique, max 254 chars), `password_hash`, `role` (`customer` | `admin`), `store_credit` (decimal, default initial balance), `is_verified` (boolean), `created_at`.
* **Product:** `id`, `name`, `description`, `price` (decimal, authoritative), `stock_quantity` (integer), `category`, `image_url`.
* **Cart / CartItem:** `id`, `user_id`, `product_id`, `quantity` (positive integer).
* **Coupon:** `id`, `code` (unique), `discount_type` (`fixed` | `percent`), `discount_value`, `is_active`, `max_uses_per_user`.
* **Order & OrderItem:** `id` (unguessable UUID/token), `user_id`, `status` (`PENDING` | `PAID` | `CANCELLED`), `applied_coupons` (JSON/relational set), `total_paid`, `created_at`, plus line-item snapshots (`product_id`, `quantity`, `unit_price_at_purchase`).