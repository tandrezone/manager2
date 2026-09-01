# manager2 — B2B trade portal

An invite-gated wholesale ordering portal for **verified trade customers**:
catalogue with tiered pricing, delivery scheduling, MB WAY / SEPA / card /
credit-terms payment, gapless hash-chained invoicing, order-scoped messaging,
credit risk management, and a working GDPR rights layer.

Native PHP 8.3+ and MariaDB 10.11+, no framework, no Composer dependencies.
Mobile-first PWA front end.

> `manager2` is a placeholder name taken from the directory. Rename the
> `Manager2\` namespace, the `manager2` database and the `M2_` environment prefix
> before you go anywhere near production.

---

## The one design decision everything else follows from

**A trade portal must know its counterparty.** Not for the operator's comfort —
because every downstream obligation depends on it. An invoice is invalid without
the customer's legal name and VAT number. Zero-rating an intra-EU supply requires
a *verified* VAT registration, and getting it wrong means the seller owes the tax.
Credit terms require someone legally answerable for the debt. You cannot enforce a
contract against a display handle.

So an account here is a **legal entity plus at least one named, contactable
human**, and `users.display_handle` is cosmetic — enough for a UI avatar so a
shared warehouse tablet does not show a full name, never an identity.

That is not in tension with data minimisation. Art. 5(1)(c) asks for data limited
to what is necessary *for the purpose*, and minimisation here shows up in what is
absent: no date of birth, no ID numbers, no home addresses, no personal contact
details, no third-party enrichment, no behavioural tracking, per-purpose
retention with an automated purge. See [docs/GDPR.md](docs/GDPR.md) §1.

Verification is a **state, not a badge**: registration yields
`pending_verification`, which can order up to a configured floor (default
EUR 250). Reaching `active` needs a KYB pass, and the gate is enforced in the
ordering path.

---

## Layout

```
db/schema.sql                    Full DDL: 20 tables, ROPA seeded
src/
  Support/Uuid.php               UUIDv7 with a monotonic counter
  Support/Db.php                 PDO factory, transaction helper, keyed IP hashing
  Support/Html.php               Escaping, money, CSRF
  Crypto/KeyRing.php             Versioned keys, HKDF per-column derivation
  Crypto/FieldCipher.php         AES-256-GCM with AEAD row binding
  Crypto/BlindIndex.php          HMAC-SHA256 searchable equality index
  Auth/Passwords.php             Argon2id + timing equalisation
  Auth/VatNumber.php             EU syntax + Portuguese NIF mod-11 checksum
  Auth/Vies.php                  VAT existence check, fails soft
  Auth/InviteService.php         Issue / resolve / consume / revoke
  Auth/Registration.php          Invite redemption + KYB onboarding
  Billing/InvoiceService.php     Gapless numbering + tamper-evident chain
  Payments/WebhookVerifier.php   Constant-time HMAC, replay window
  Payments/PaymentWebhookController.php   Verify → claim → reconcile → settle
  Notify/                        Email of record + signed chat webhook
  Audit/AuditLog.php             Append-only hash-chained trail
  Gdpr/DsarService.php           Access, portability, erasure with legal hold
  Gdpr/RetentionPurger.php       ROPA-driven purge, dry-run first
  Credit/CreditDecisionService.php   Explainable, contestable scoring
templates/checkout.php           Mobile-first checkout
public/assets/app.css            Tokenised, dark mode, reduced-motion
public/manifest.json             PWA manifest
public/sw.js                     Service worker (never caches business data)
public/webhooks/payment.php      Thin webhook endpoint
bin/selftest-crypto.php          40 assertions, no database needed
bin/selftest-integration.php     81 assertions against a live MariaDB
docs/SECURITY.md                 Argon2id, envelope encryption, webhooks
docs/GDPR.md                     ROPA, DSAR, Art. 22, breach register
```

---

## Setup

```bash
# 1. Keys — four independent secrets
for k in M2_FIELD_KEY_V1 M2_BLIND_INDEX_KEY_V1 M2_INVITE_PEPPER M2_IP_HASH_KEY; do
  echo "$k=\"$(openssl rand -base64 32)\""
done

cp .env.example .env    # paste them in, add DB credentials and the PSP secret

# 2. Schema
mariadb < db/schema.sql

# 3. Least-privilege application user — no DROP, and no DELETE on the
#    append-only tables
mariadb -e "
  CREATE USER 'manager2_app'@'localhost' IDENTIFIED BY '<password>';
  GRANT SELECT, INSERT, UPDATE ON manager2.* TO 'manager2_app'@'localhost';
  GRANT DELETE ON manager2.sessions TO 'manager2_app'@'localhost';
  GRANT DELETE ON manager2.audit_log TO 'manager2_app'@'localhost';
"

# 4. Verify
php bin/selftest-crypto.php
M2_DB_DSN='mysql:host=127.0.0.1;dbname=manager2;charset=utf8mb4' \
  M2_DB_USER=root php bin/selftest-integration.php
```

Point the web root at `public/`, and serve `manifest.json`, `sw.js` and
`offline.html` from the origin root — a service worker's scope is limited by its
own path.

### First staff account

Bootstrap one directly (there is no invite to redeem yet), then everything else
flows through invitations:

```php
$c = m2_container();
$issued = $c['invites']->issue(
    issuedByUserId:      $staffUserId,
    intendedLegalName:   'Padaria Central, Lda.',
    intendedVatNumber:   'PT501442600',
    intendedCountry:     'PT',
    recipientEmail:      'ana@padariacentral.pt',
    grantsRole:          'org_admin',
    reason:              'Trade show lead, credit-checked'
);
// $issued['code'] === 'K7M2Q-4XPWR-...'  — shown once, never stored
```

---

## Scheduled jobs

| Frequency | Job | Why |
|---|---|---|
| Daily | `DsarService::overdueAndDueSoon()` | A missed Art. 12(3) deadline is itself an infringement |
| Daily | `CreditDecisionService::overdueReviews()` | Art. 22(3) human-review SLA |
| Nightly | `AuditLog::verify()` | Detects tampering; alert on anything but clean |
| Nightly | `InvoiceService::verifySeries()` | Detects gaps and altered documents |
| Nightly | Ship `AuditLog::chainHead()` off-box | An external anchor is what makes the chain meaningful |
| Weekly | `RetentionPurger::plan()` then `execute()` | Art. 5(1)(e). Dry-run first, always |
| Annually | `InvoiceService::ensureSeries(Y+1)` | Before 1 January, or issuing fails |

---

## Verification

```
bin/selftest-crypto.php        40 passed    (no database required)
bin/selftest-integration.php   81 passed    (MariaDB 10.11)
```

The suites deliberately assert the **negative** cases, which is where this kind
of code actually fails:

- ciphertext moved between rows, columns or tables → rejected
- one flipped bit, or truncation → rejected
- forged, unsigned, stale or tampered webhook → 400, nothing recorded
- replayed webhook → 200 `already_processed`, no duplicate payment
- underpayment, overpayment, currency mismatch, unknown order → 409 + urgent alert
- reused invite, wrong recipient, mismatched company, invalid VAT → rejected
- identical rejection message across every invite failure mode
- weak password rejected *before* the invite is consumed
- modified invoice → detected; deleted invoice → gap detected
- deleted or modified audit entry → detected
- erasure → contact PII gone, **invoices retained** with Art. 17(3)(b) cited
- notifications carrying contact PII → refused at construction

Four real bugs were found this way and fixed: a credit-scoring key that was never
set, DSAR clock skew that computed a 29-day statutory deadline, `invoices.settled_at`
never populated (so nothing ever counted as settled), and — the interesting one —
an on-time-payment bonus gated on `AVG(days_late)`, which is zero over zero
settled invoices, so an account that had never paid anything scored as a model
payer. Absence of evidence read as evidence of good conduct, in the direction
that extends credit.

---

## Not implemented

The pieces below are deliberately out of scope for this pass, listed so nothing
looks finished that is not.

- Session and login controllers. `Passwords`, `sessions`, `failed_login_count`
  and `locked_until` are ready; the enforcement is not written.
- **Tenant scoping.** Every customer-facing query must be scoped by `org_id` from
  the *session*, never a request parameter. This is the likeliest serious
  vulnerability in a multi-tenant portal — `/orders/ORD-2026-000148` must 404 for
  another tenant, not render.
- Manager dashboard UI. `v_org_metrics` provides the CRM aggregates and
  `orders.idx_orders_queue` supports queue sorting; the BI charts and the
  acceptance screens are not built.
- Catalogue and cart controllers; `product_prices` tier resolution.
- PDF invoice rendering, and the Portuguese AT certification route
  (SECURITY.md §4).
- MFA enrolment flow.
- Icon and screenshot assets referenced by `manifest.json`.

## Before production

Work through the checklist in [docs/SECURITY.md](docs/SECURITY.md) §5 and the
outstanding items in [docs/GDPR.md](docs/GDPR.md) §9. The two that are least
likely to be someone else's job and most likely to hurt:

1. **Never withdraw a key version while ciphertext still references it.** Verify
   with a count, not with confidence. That data is gone.
2. **Get the Portuguese invoicing route reviewed by a tax adviser** before
   issuing a real invoice. Certified software is a legal requirement, and
   SHA-256 chaining is not a substitute for it.
