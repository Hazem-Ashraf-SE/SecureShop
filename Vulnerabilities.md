Attacks and Vulnerabilities:
----------------------------
## 1. Practical Lab Exploits

1. Excessive Trust in Client-Side Controls (Price Tampering)
2. Flawed Enforcement of Business Rules (Coupon Stacking / Alternating Codes)
3. Inconsistent Handling of Exceptional Input (Email Truncation & Admin Privilege Escalation)
4. Insufficient Workflow Validation (Checkout/Payment Bypass via Request Replay)
5. 2FA Broken Logic (Client-Side `verify` Cookie Hijacking & 4-Digit OTP Brute-Force)

## 2. Defensive Lab Threats & Attacks

1. Account Takeover (ATO)
2. Automated Bot / Credential Pasting
3. Imposter / Unfamiliar Manual Typing
4. Behavioral Profile Poisoning (Learning from Untrusted Logins)
5. Sensitive Keystroke Data Exposure
6. **Plaintext / Weak Password Storage** (Added — Lab 4)
7. Password Phishing
8. Remote / Out-of-Region Logins
9. Off-Hours Access
10. Coordinate / GPS Spoofing
11. OTP Code Capture / Replay
12. Cryptographic Signature Tampering (Flipped Byte) & Credential ID Mismatch

## 3. Business Logic Vulnerabilities (Full Catalog)

1. Excessive Trust in Client-Side Controls
2. High-Level Logic Vulnerability
3. Inconsistent Security Controls
4. Flawed Enforcement of Business Rules
5. Low-Level Logic Flaw
6. Inconsistent Handling of Exceptional Input
7. Weak Isolation on a Dual-Use Endpoint
8. Insufficient Workflow Validation
9. Authentication Bypass via Flawed State Machine
10. Infinite Money Logic Flaw
11. Authentication Bypass via Encryption Oracle

## 4. General Web Attacks & Recon

1. Man-in-the-Middle (MitM) Interception
2. Cross-Site Scripting (XSS)
3. SQL Injection (SQLi)
4. Directory Traversal
5. Data Leaks (Response Body Exposure)
6. **Redirect Attack Surface Exposure** (Added — Lab 1)
7. Input Validation Bypass
8. Brute-Force Attacks & Automated Fuzzing
9. Privilege Escalation & Access Control Bypasses
10. Directory Enumeration & Hidden Endpoint Reconnaissance
11. Backend Crash Exploitation (`500 Internal Server Error` Probing)
