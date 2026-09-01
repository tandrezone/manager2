# Security implementation guide

Covers the three mechanisms that carry most of the weight: password hashing,
field-level encryption, and webhook verification. Each section states what the
mechanism defends against and — more usefully — what it does not.

---

## 1. Password hashing — Argon2id

`src/Auth/Passwords.php`

```php
password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64 MiB
    'time_cost'   => 3,      // passes
    'threads'     => 2,      // lanes
]);
```

**Why Argon2id.** Memory-hard, so an attacker with GPUs or ASICs gains far less
advantage than against bcrypt or PBKDF2. The `id` variant combines Argon2i's
side-channel resistance on the first pass with Argon2d's GPU resistance on later
passes; RFC 9106 recommends it for password storage.

**Tuning.** Target 250–500 ms per hash on production hardware. Faster wastes
available security. Much slower turns your own login endpoint into a DoS
amplifier.

The trap is memory, not time. 64 MiB is *per concurrent hash*. Fifty
simultaneous logins is 3.2 GiB. Size `pm.max_children` against that, or the
first credential-stuffing wave OOMs the box rather than being repelled by it.
Measure before shipping:

```bash
php -r '$t=microtime(true); password_hash("x", PASSWORD_ARGON2ID,
  ["memory_cost"=>65536,"time_cost"=>3,"threads"=>2]);
  printf("%.0f ms\n", (microtime(true)-$t)*1000);'
```

**Upgrade on login.** `password_needs_rehash()` is checked on every successful
authentication and the hash rewritten if policy has moved. That is the only
moment the plaintext exists to rehash with.

**Timing equalisation.** `verify()` runs a dummy hash when the account does not
exist. Without it, a missing account returns in microseconds while a real one
takes ~300 ms, and the login endpoint becomes an account-enumeration oracle.
Callers must therefore always reach `verify()`, even when the user lookup found
nothing. `bin/selftest-crypto.php` asserts the two paths stay within a factor of
two.

**No pepper, deliberately.** A pepper protects only against an attacker holding
the database but not the application secrets — the same threat model the field
encryption already addresses — while permanently coupling every stored hash to a
secret that cannot be rotated without a global password reset. If you disagree,
HMAC the password with a *versioned* pepper before hashing and store the version.

**Policy.** Minimum 12 characters, maximum 4096 bytes (a DoS bound, not a
security one), plus a breach-corpus check. No composition rules — those push
users toward `P@ssw0rd1!`, which is worse than `correct horse battery staple` on
every axis. Wire `isObviouslyGuessable()` to a Have I Been Pwned k-anonymity
range query for real coverage.

---

## 2. Field-level encryption — AES-256-GCM

`src/Crypto/FieldCipher.php`, `KeyRing.php`, `BlindIndex.php`

### Sealed layout

Stored raw in `VARBINARY`. Flat 31-byte overhead, so size columns as
`VARBINARY(31 + max_plaintext_bytes)`.

| offset | size | field |
|-------:|-----:|-------|
| 0 | 1 | format magic (`0x01`) |
| 1 | 2 | key version, big-endian uint16 |
| 3 | 12 | nonce (96-bit, GCM-native) |
| 15 | 16 | authentication tag |
| 31 | … | ciphertext |

### Key hierarchy

```
KMS / environment root  ─┬─ field root         (M2_FIELD_KEY_V*)
                         └─ blind-index root   (M2_BLIND_INDEX_KEY_V*)
                                │
              HKDF-SHA256, info = "manager2|<purpose>|<table>|<column>"
                                │
                         per-column 256-bit subkey
```

Two independent roots, so compromising the searchable index does not yield
plaintext. Per-column derivation bounds the data under any single key and
prevents a ciphertext from one column being replayed into another.

Key material never enters MariaDB. The `encryption_keys` table tracks only which
versions exist and their lifecycle.

### The part that is easy to skip

Every seal binds `table|column|row-id` as AEAD associated data:

```php
$cipher->seal($address, 'delivery_locations', 'address_enc', $rowId);
```

Without it, anyone with `UPDATE` — or a buggy bulk job — can copy a ciphertext
from one row into another and it decrypts cleanly, silently attributing one
person's address or phone number to another. With it, the tag check fails. This
is why primary keys are UUIDv7 generated in PHP: the id must exist *before* the
`INSERT` to be bound into the seal.

`bin/selftest-crypto.php` asserts the negative cases: ciphertext moved between
rows, between columns, between tables, a single flipped bit, and truncation are
all rejected.

### Searchable encryption

Randomised GCM means `WHERE email_enc = ?` can never match. Login still has to
find a user by email, so:

```php
email_bidx = HMAC-SHA256(column_subkey, normalise(email))
```

**What this leaks: equality.** An attacker with the table sees *that* two
accounts share an email or phone number. They cannot recover a value from the
index alone, but a low-entropy domain is brute-forceable *if the index key is
also compromised*. Therefore: index only what genuinely needs exact-match
lookup, never a low-entropy field where correlation would be sensitive, and
expect no range or prefix search.

Normalisation must be stable forever. Change the rule and every stored index
silently stops matching, which needs a rebuild migration exactly like a key
rotation. Email is fully lowercased (RFC 5321 says the local part is
case-sensitive; no provider behaves that way, and treating `A@x.com` and
`a@x.com` as different accounts causes worse problems than the spec deviation).
Gmail dot and `+tag` aliases are deliberately *not* collapsed — that would merge
addresses users consider distinct.

### Rotation

1. Add `M2_FIELD_KEY_V2`, set `M2_FIELD_KEY_ACTIVE=2`. New writes seal under v2;
   reads accept any loaded version.
2. Run the re-encryption sweep. `FieldCipher::needsRotation()` identifies rows.
3. Only once no row references v1 may that material be withdrawn.

**Withdrawing a key whose ciphertext still exists destroys that data
permanently.** Verify with a count, not with confidence.

During a blind-index rotation, look up with
`BlindIndex::computeAllVersions()` and `WHERE email_bidx IN (?, ?)` so nobody is
locked out mid-migration.

### Threat model, honestly

**Defends against:** stolen disks and backups, a read-only SQL injection, a
leaked replica, an over-broad support query, a hosting provider reading the
volume.

**Does not defend against:** an attacker holding the application key material.
The running application must decrypt to do its job. Field encryption narrows the
blast radius of a data-at-rest compromise; it does not make the application
trustless, and the privacy notice must not imply otherwise.

This is why `AuditLog` exists and is not optional. Encryption limits who *can*
read PII; the audit log records who *did*. A system that encrypts aggressively
but keeps no access record is not privacy-preserving, it is opaque — including to
the people whose data it holds and to whoever has to answer for it.

### Also required, and not provided by this layer

- **TLS to the database.** Field encryption protects data at rest, not in
  flight. Set `M2_DB_SSL_CA` for any non-local database.
- **Encryption at rest for the volume.** Field encryption covers the columns
  named; InnoDB's redo log, binlogs and temp files can still spill plaintext.
  Enable full-disk or tablespace encryption underneath.
- **Backup key custody.** A backup you cannot decrypt is not a backup. A backup
  whose keys sit beside it is not encrypted.

---

## 3. Webhook signature verification

`src/Payments/WebhookVerifier.php`

A payment webhook endpoint is an unauthenticated public URL that moves money in
your database. Six rules, each of which has cost somebody real money:

**1. Verify against the raw body.** Signatures cover exact bytes.
`json_decode` → `json_encode` changes key order, whitespace, unicode escaping
and float formatting, so a re-serialised body will not verify — and the usual
"fix" is to stop verifying. Read `php://input` once, verify, *then* parse.

**2. Compare in constant time.** `==` on a signature leaks a byte-at-a-time
timing oracle that permits forgery in a few thousand requests. `hash_equals`
only.

**3. Bind a timestamp.** A signature alone is replayable forever. Sign
`timestamp . "." . body` and reject outside a 300-second window.

**4. Be idempotent anyway.** PSPs retry, sometimes for days, sometimes
concurrently. `UNIQUE (provider, event_id)` is the real defence; the timestamp
window only bounds the replay horizon. The `INSERT` *is* the claim, so two
concurrent retries cannot both proceed.

**5. Fail closed, say nothing.** Any verification failure is a bare 400.
Explaining whether the signature or the timestamp failed halves the work of
forging one.

**6. Never trust the amount in the payload.** A valid signature proves the
message came from the PSP, not that the amount matches what was ordered.
Underpayment, currency drift and partial captures all arrive correctly signed.
`PaymentWebhookController` reconciles against the order and returns **409** — a
conflict a retry cannot fix — distinct from the 400 for a forgery and the 500
that asks the PSP to retry.

### Secret rotation

The header parser accepts multiple comma-separated signatures and compares all
candidates in constant time, so a provider that sends both old and new during a
rotation verifies throughout.

### Deployment

- Terminate TLS in front. A signature over plaintext still leaks order
  references and amounts.
- Rate-limit at the edge. An HMAC per request is cheap but not free.
- Restrict by source IP where the provider publishes a range — defence in depth,
  never a substitute for the signature.

---

## 4. Invoice integrity

`src/Billing/InvoiceService.php`

Gapless sequential numbering allocated under `SELECT … FOR UPDATE`, plus a
hash chain:

```
doc_hash = SHA256(prev_hash || canonical_document_string)
```

`verifySeries()` detects both a modified document and a deleted one (a gap),
which the test suite asserts. Note the operational consequence of gaplessness:
allocation must be the **last fallible step**. Never allocate a number and then
call a PDF renderer or a mail service in the same transaction — if that fails you
have burned a number, and a gap reads as a suppressed sale.

**Portugal.** This is a correct foundation, not a certified solution. Portuguese
law requires invoicing software certified by the Autoridade Tributária, documents
signed with an RSA-2048 key registered with the AT, an ATCUD from an AT-issued
series validation code, a QR code on the printed document, and monthly SAF-T (PT)
export. SHA-256 chaining substitutes for none of that. The code omits the ATCUD
rather than fabricating a plausible one. **Get a tax adviser to confirm your
certification route before issuing a real invoice.**

---

## 5. Application security checklist

Not implemented by the classes above; needed before production.

- [ ] **Session cookies:** `HttpOnly`, `Secure`, `SameSite=Lax`, regenerate id on
      privilege change, absolute and idle timeouts. Sessions are hashed in the
      `sessions` table so a database read yields no usable tokens.
- [ ] **CSRF:** `Html::csrfToken()` / `csrfValid()` on every state-changing POST.
      `SameSite=Lax` alone does not cover top-level POST navigation everywhere.
- [ ] **Rate limiting and lockout:** `users.failed_login_count` and `locked_until`
      exist; the enforcement belongs in the login controller. Rate-limit per
      account *and* per IP — per-account alone lets one IP spray thousands of
      accounts.
- [ ] **MFA:** `totp_secret_enc` and `mfa_enforced_at` are in the schema.
      Mandatory for `admin`, `finance` and `dpo` roles.
- [ ] **Authorisation on every query.** Every customer-facing query must be
      scoped by `org_id` from the session, never from a request parameter. This
      is the most likely serious vulnerability in a multi-tenant portal:
      `/orders/ORD-2026-000148` must 404 for another tenant, not render.
- [ ] **Output escaping:** `Html::e()` on every interpolation.
- [ ] **Security headers:** HSTS, `Content-Security-Policy` (the templates use no
      inline styles and one inline script — give it a nonce),
      `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.
- [ ] **Least-privilege database user.** The application needs no `DROP`, and no
      `DELETE` on `audit_log` or `invoices`.
- [ ] **Audit chain anchoring.** Ship `AuditLog::chainHead()` off-box on a
      schedule. Without an external anchor, an attacker with `UPDATE` can rewrite
      the whole chain consistently.
- [ ] **Nightly verification jobs:** `AuditLog::verify()`,
      `InvoiceService::verifySeries()`, `DsarService::overdueAndDueSoon()`,
      `CreditDecisionService::overdueReviews()`. Alert on anything but a clean
      result.
