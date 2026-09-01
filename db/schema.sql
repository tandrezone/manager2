-- =============================================================================
-- manager2 — B2B Trade Portal
-- Target: MariaDB 10.11 LTS / 11.x  (InnoDB, utf8mb4)
--
-- CONVENTIONS
--   id BINARY(16)      UUIDv7, generated in PHP (time-ordered => good index
--                      locality, and available *before* INSERT so it can be
--                      bound into the AEAD associated data of encrypted columns).
--   *_enc VARBINARY    AES-256-GCM sealed blob. Layout documented in
--                      src/Crypto/FieldCipher.php. Never queryable directly.
--   *_bidx BINARY(32)  HMAC-SHA256 blind index over the normalised plaintext.
--                      Enables exact-match lookup on an encrypted column
--                      without giving the DB the plaintext.
--   *_cents BIGINT     Money. Integer minor units only — never floats.
--   *_bp INT           Basis points (tax_rate_bp 2300 = 23.00%).
--
-- WHAT IS **NOT** ENCRYPTED, DELIBERATELY
--   Legal entity name, VAT number and registered address of a trade customer
--   are public commercial-registry data. Encrypting them buys nothing and
--   breaks VIES reconciliation, invoice rendering and tax reporting.
--   Encryption is applied to natural-person data: names, emails, phones,
--   delivery contacts, message bodies.
-- =============================================================================

SET NAMES utf8mb4;

CREATE DATABASE IF NOT EXISTS manager2
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE manager2;

-- -----------------------------------------------------------------------------
-- 1. RECORD OF PROCESSING ACTIVITIES (GDPR Art. 30)
--    The ROPA lives in the database, not in a spreadsheet that rots, because
--    RetentionPurger reads retention_days straight off it. Compliance that is
--    executable is compliance that stays true.
-- -----------------------------------------------------------------------------
CREATE TABLE processing_purposes (
  id                    BINARY(16)   NOT NULL,
  code                  VARCHAR(64)  NOT NULL,
  purpose               VARCHAR(255) NOT NULL,
  lawful_basis          ENUM('contract','legal_obligation','legitimate_interest',
                             'consent','vital_interests','public_task') NOT NULL,
  basis_note            TEXT             NULL,
  data_categories       JSON         NOT NULL,
  retention_days        INT UNSIGNED     NULL,  -- NULL = retained while contract is live
  retention_note        TEXT             NULL,
  recipients            JSON             NULL,
  transfers_outside_eea TINYINT(1)   NOT NULL DEFAULT 0,
  transfer_safeguard    VARCHAR(255)     NULL,
  lia_ref               VARCHAR(255)     NULL,  -- legitimate interests assessment
  created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                     ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_purpose_code (code)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 2. ENCRYPTION KEY REGISTRY
--    Key *material* never lands here — it lives in the KMS / environment.
--    This table tracks which versions exist and their lifecycle, so a
--    rotation can be driven and audited, and so re-encryption progress is
--    measurable.
-- -----------------------------------------------------------------------------
CREATE TABLE encryption_keys (
  key_version   SMALLINT UNSIGNED NOT NULL,
  purpose       ENUM('field','blind_index') NOT NULL,
  status        ENUM('pending','active','retiring','retired') NOT NULL DEFAULT 'pending',
  kms_ref       VARCHAR(255)  NOT NULL,
  activated_at  DATETIME(6)       NULL,
  retired_at    DATETIME(6)       NULL,
  created_at    DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (key_version, purpose),
  KEY idx_keys_status (purpose, status)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 3. TRADE CUSTOMERS (legal entities)
--    A counterparty is an identified business. Credit terms, invoices and
--    contract enforcement are all impossible against an anonymous handle,
--    so identity is a column constraint, not an afterthought.
-- -----------------------------------------------------------------------------
CREATE TABLE organisations (
  id                  BINARY(16)   NOT NULL,
  account_ref         VARCHAR(20)  NOT NULL,          -- human-quotable, e.g. 'ACC-004821'
  legal_name          VARCHAR(255) NOT NULL,
  trading_name        VARCHAR(255)     NULL,
  legal_form          VARCHAR(64)      NULL,
  country             CHAR(2)      NOT NULL,          -- ISO 3166-1 alpha-2
  vat_number          VARCHAR(20)      NULL,          -- e.g. PT123456789
  vat_valid           TINYINT(1)       NULL,          -- last VIES answer
  vat_checked_at      DATETIME(6)      NULL,
  vat_check_ref       VARCHAR(64)      NULL,          -- VIES consultation number
  registry_number     VARCHAR(64)      NULL,
  registered_address  TEXT             NULL,          -- public registry data
  status              ENUM('pending_verification','active','on_hold',
                           'suspended','closed') NOT NULL DEFAULT 'pending_verification',
  status_reason        VARCHAR(255)    NULL,
  price_tier          ENUM('standard','volume','key_account') NOT NULL DEFAULT 'standard',
  currency            CHAR(3)      NOT NULL DEFAULT 'EUR',
  credit_limit_cents  BIGINT       NOT NULL DEFAULT 0,
  payment_terms_days  SMALLINT     NOT NULL DEFAULT 0, -- 0 = prepay
  tax_exempt          TINYINT(1)   NOT NULL DEFAULT 0, -- intra-EU reverse charge
  onboarded_at        DATETIME(6)      NULL,
  created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                   ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_org_account_ref (account_ref),
  UNIQUE KEY uq_org_vat (country, vat_number),
  KEY idx_org_status (status),
  KEY idx_org_tier (price_tier, status)
) ENGINE=InnoDB;

-- Know-Your-Business evidence trail. An account reaching 'active' must be
-- explainable: who checked what, when, against which source.
CREATE TABLE kyb_checks (
  id                BINARY(16)  NOT NULL,
  org_id            BINARY(16)  NOT NULL,
  check_type        ENUM('vies_vat','company_registry','proof_of_address',
                         'bank_account','beneficial_owner','sanctions_screen',
                         'manual_review') NOT NULL,
  outcome           ENUM('pass','fail','inconclusive','waived') NOT NULL,
  source            VARCHAR(128)    NULL,             -- 'VIES', 'Portal da Justiça', ...
  evidence_ref      VARCHAR(255)    NULL,             -- object-store key, not the doc itself
  evidence_sha256   BINARY(32)      NULL,
  notes_enc         VARBINARY(4096) NULL,
  performed_by      BINARY(16)      NULL,             -- staff user
  performed_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at        DATETIME(6)     NULL,             -- periodic re-verification
  PRIMARY KEY (id),
  KEY idx_kyb_org (org_id, performed_at),
  KEY idx_kyb_expiry (expires_at),
  CONSTRAINT fk_kyb_org FOREIGN KEY (org_id) REFERENCES organisations (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 4. USERS — named natural persons acting for an organisation.
--    display_handle exists for UI chrome only. It is never a substitute for
--    knowing who bound the company to an order.
-- -----------------------------------------------------------------------------
CREATE TABLE users (
  id                  BINARY(16)   NOT NULL,
  org_id              BINARY(16)       NULL,   -- NULL for internal staff
  kind                ENUM('customer','staff') NOT NULL DEFAULT 'customer',
  role                ENUM('buyer','approver','org_admin',
                           'sales','ops','finance','admin','dpo') NOT NULL,
  email_enc           VARBINARY(512) NOT NULL,
  email_bidx          BINARY(32)     NOT NULL,
  full_name_enc       VARBINARY(512) NOT NULL,
  job_title_enc       VARBINARY(512)     NULL,
  phone_enc           VARBINARY(256)     NULL,
  phone_bidx          BINARY(32)         NULL,
  display_handle      VARCHAR(64)    NOT NULL,  -- cosmetic only
  password_hash       VARCHAR(255)       NULL,  -- NULL until invite accepted
  password_set_at     DATETIME(6)        NULL,
  must_change_password TINYINT(1)    NOT NULL DEFAULT 0,
  totp_secret_enc     VARBINARY(256)     NULL,
  mfa_enforced_at     DATETIME(6)        NULL,
  status              ENUM('invited','active','locked','disabled') NOT NULL DEFAULT 'invited',
  failed_login_count  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until        DATETIME(6)        NULL,
  last_login_at       DATETIME(6)        NULL,
  last_login_ip_hash  BINARY(32)         NULL,  -- hashed: an IP is personal data
  can_authorise_cents BIGINT         NOT NULL DEFAULT 0, -- per-order spend authority
  erased_at           DATETIME(6)        NULL,  -- Art. 17 pseudonymisation marker
  created_at          DATETIME(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at          DATETIME(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                     ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email_bidx (email_bidx),
  KEY idx_users_org (org_id, status),
  KEY idx_users_phone_bidx (phone_bidx),
  KEY idx_users_role (kind, role),
  KEY idx_users_erased (erased_at),
  CONSTRAINT fk_users_org FOREIGN KEY (org_id) REFERENCES organisations (id)
) ENGINE=InnoDB;

CREATE TABLE sessions (
  id             BINARY(32)  NOT NULL,          -- SHA-256 of the session token
  user_id        BINARY(16)  NOT NULL,
  ip_hash        BINARY(32)      NULL,
  user_agent_hash BINARY(32)     NULL,
  created_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at     DATETIME(6) NOT NULL,
  revoked_at     DATETIME(6)     NULL,
  PRIMARY KEY (id),
  KEY idx_sessions_user (user_id, expires_at),
  KEY idx_sessions_expiry (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 5. INVITES — access control for a closed trade portal.
--    An invite is an *onboarding* control: it records who issued it and which
--    business it is for, and it commits the recipient to KYB. The plaintext
--    code is never stored, only a hash, so a database read does not yield
--    working invitations.
-- -----------------------------------------------------------------------------
CREATE TABLE invites (
  id                   BINARY(16)   NOT NULL,
  code_hash            BINARY(32)   NOT NULL,   -- HMAC-SHA256(pepper, code)
  code_prefix          VARCHAR(8)   NOT NULL,   -- first chars, for support lookup
  org_id               BINARY(16)       NULL,   -- set = join existing account
  intended_legal_name  VARCHAR(255)     NULL,   -- set = onboard a new account
  intended_vat_number  VARCHAR(20)      NULL,
  intended_country     CHAR(2)          NULL,
  email_bidx           BINARY(32)       NULL,   -- lock the invite to one recipient
  grants_role          ENUM('buyer','approver','org_admin') NOT NULL DEFAULT 'buyer',
  issued_by            BINARY(16)   NOT NULL,
  issued_reason        VARCHAR(255)     NULL,
  max_uses             SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  uses                 SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at           DATETIME(6)  NOT NULL,
  revoked_at           DATETIME(6)      NULL,
  revoked_by           BINARY(16)       NULL,
  first_accepted_at    DATETIME(6)      NULL,
  created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_invite_code_hash (code_hash),
  KEY idx_invite_prefix (code_prefix),
  KEY idx_invite_org (org_id),
  KEY idx_invite_expiry (expires_at, revoked_at),
  CONSTRAINT fk_invite_org FOREIGN KEY (org_id) REFERENCES organisations (id),
  CONSTRAINT fk_invite_issuer FOREIGN KEY (issued_by) REFERENCES users (id)
) ENGINE=InnoDB;

CREATE TABLE invite_redemptions (
  id          BINARY(16)  NOT NULL,
  invite_id   BINARY(16)  NOT NULL,
  user_id     BINARY(16)  NOT NULL,
  ip_hash     BINARY(32)      NULL,
  redeemed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_redemption (invite_id, user_id),
  CONSTRAINT fk_red_invite FOREIGN KEY (invite_id) REFERENCES invites (id),
  CONSTRAINT fk_red_user   FOREIGN KEY (user_id)   REFERENCES users (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 6. CATALOGUE
-- -----------------------------------------------------------------------------
CREATE TABLE products (
  id             BINARY(16)   NOT NULL,
  sku            VARCHAR(64)  NOT NULL,
  name           VARCHAR(255) NOT NULL,
  description    TEXT             NULL,
  category       VARCHAR(128)     NULL,
  uom            VARCHAR(16)  NOT NULL DEFAULT 'unit',  -- unit / kg / case
  units_per_case INT UNSIGNED NOT NULL DEFAULT 1,
  list_price_cents BIGINT     NOT NULL,
  tax_rate_bp    INT          NOT NULL DEFAULT 2300,
  min_order_qty  INT UNSIGNED NOT NULL DEFAULT 1,
  order_multiple INT UNSIGNED NOT NULL DEFAULT 1,
  stock_qty      INT          NOT NULL DEFAULT 0,
  stock_reserved INT          NOT NULL DEFAULT 0,
  lead_time_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  hs_code        VARCHAR(16)      NULL,          -- customs classification
  unit_cost_cents BIGINT      NOT NULL DEFAULT 0, -- for margin analytics
  is_active      TINYINT(1)   NOT NULL DEFAULT 1,
  created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                              ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_products_sku (sku),
  KEY idx_products_active (is_active, category)
) ENGINE=InnoDB;

-- Tiered / volume break pricing — the normal shape of wholesale pricing.
CREATE TABLE product_prices (
  id          BINARY(16)   NOT NULL,
  product_id  BINARY(16)   NOT NULL,
  price_tier  ENUM('standard','volume','key_account') NOT NULL,
  min_qty     INT UNSIGNED NOT NULL DEFAULT 1,
  price_cents BIGINT       NOT NULL,
  valid_from  DATE             NULL,
  valid_to    DATE             NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_price_break (product_id, price_tier, min_qty, valid_from),
  CONSTRAINT fk_price_product FOREIGN KEY (product_id) REFERENCES products (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 7. DELIVERY LOCATIONS — encrypted, because a site address plus a named
--    contact is personal data under Art. 4(1) even in a B2B setting.
-- -----------------------------------------------------------------------------
CREATE TABLE delivery_locations (
  id                    BINARY(16)   NOT NULL,
  org_id                BINARY(16)   NOT NULL,
  label                 VARCHAR(64)  NOT NULL,   -- 'Main warehouse'
  address_enc           VARBINARY(2048) NOT NULL,
  postcode_bidx         BINARY(32)       NULL,   -- routing/zone lookup
  country               CHAR(2)      NOT NULL,
  contact_name_enc      VARBINARY(512)   NULL,
  contact_phone_enc     VARBINARY(256)   NULL,
  access_notes_enc      VARBINARY(2048)  NULL,   -- 'loading bay, ring bell'
  opening_hours         JSON             NULL,
  is_default            TINYINT(1)   NOT NULL DEFAULT 0,
  archived_at           DATETIME(6)      NULL,
  created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                     ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_dloc_org (org_id, archived_at),
  CONSTRAINT fk_dloc_org FOREIGN KEY (org_id) REFERENCES organisations (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 8. ORDERS
-- -----------------------------------------------------------------------------
CREATE TABLE orders (
  id                    BINARY(16)   NOT NULL,
  order_number          VARCHAR(24)  NOT NULL,   -- ORD-2026-000148
  org_id                BINARY(16)   NOT NULL,
  placed_by             BINARY(16)   NOT NULL,
  approved_by           BINARY(16)       NULL,   -- customer-side approver
  customer_po_ref       VARCHAR(64)      NULL,   -- their purchase order number
  status                ENUM('draft','submitted','accepted','declined',
                             'picking','dispatched','delivered',
                             'cancelled','closed') NOT NULL DEFAULT 'draft',
  currency              CHAR(3)      NOT NULL DEFAULT 'EUR',
  net_cents             BIGINT       NOT NULL DEFAULT 0,
  tax_cents             BIGINT       NOT NULL DEFAULT 0,
  gross_cents           BIGINT       NOT NULL DEFAULT 0,
  cogs_cents            BIGINT       NOT NULL DEFAULT 0,  -- snapshot for margin BI
  payment_method        ENUM('mbway','sepa_transfer','card',
                             'credit_terms','cash_on_delivery') NOT NULL,
  payment_status        ENUM('not_required','pending','authorised','paid',
                             'partially_paid','failed','refunded') NOT NULL DEFAULT 'pending',
  paid_at               DATETIME(6)      NULL,
  delivery_location_id  BINARY(16)       NULL,
  requested_window_start DATETIME(6)     NULL,
  requested_window_end  DATETIME(6)      NULL,
  delivery_notes_enc    VARBINARY(2048)  NULL,
  promised_at           DATETIME(6)      NULL,   -- ops commitment to customer
  dispatch_method       ENUM('own_fleet','carrier','courier','collection') NULL,
  carrier               VARCHAR(64)      NULL,
  tracking_ref          VARCHAR(128)     NULL,
  dispatched_at         DATETIME(6)      NULL,
  delivered_at          DATETIME(6)      NULL,
  pod_ref               VARCHAR(255)     NULL,   -- proof of delivery object key
  pod_signed_name_enc   VARBINARY(512)   NULL,
  accepted_by           BINARY(16)       NULL,   -- staff who accepted
  accepted_at           DATETIME(6)      NULL,
  declined_reason       VARCHAR(255)     NULL,
  cancelled_reason      VARCHAR(255)     NULL,
  created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                     ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_orders_number (order_number),
  KEY idx_orders_org_created (org_id, created_at),
  KEY idx_orders_status (status, created_at),
  KEY idx_orders_queue (status, promised_at),
  KEY idx_orders_payment (payment_status, created_at),
  KEY idx_orders_delivery_window (requested_window_start),
  CONSTRAINT fk_orders_org      FOREIGN KEY (org_id) REFERENCES organisations (id),
  CONSTRAINT fk_orders_placedby FOREIGN KEY (placed_by) REFERENCES users (id),
  CONSTRAINT fk_orders_dloc     FOREIGN KEY (delivery_location_id)
                                REFERENCES delivery_locations (id)
) ENGINE=InnoDB;

CREATE TABLE order_items (
  id              BINARY(16)   NOT NULL,
  order_id        BINARY(16)   NOT NULL,
  product_id      BINARY(16)       NULL,   -- nullable: product may be retired later
  sku_snapshot    VARCHAR(64)  NOT NULL,   -- immutable record of what was sold
  name_snapshot   VARCHAR(255) NOT NULL,
  qty             INT UNSIGNED NOT NULL,
  unit_price_cents BIGINT      NOT NULL,
  tax_rate_bp     INT          NOT NULL,
  unit_cost_cents BIGINT       NOT NULL DEFAULT 0,
  net_cents       BIGINT       NOT NULL,
  tax_cents       BIGINT       NOT NULL,
  line_no         SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_order_line (order_id, line_no),
  KEY idx_items_product (product_id),
  CONSTRAINT fk_items_order   FOREIGN KEY (order_id) REFERENCES orders (id),
  CONSTRAINT fk_items_product FOREIGN KEY (product_id) REFERENCES products (id)
) ENGINE=InnoDB;

CREATE TABLE order_status_history (
  id          BINARY(16)  NOT NULL,
  order_id    BINARY(16)  NOT NULL,
  from_status VARCHAR(32)     NULL,
  to_status   VARCHAR(32) NOT NULL,
  changed_by  BINARY(16)      NULL,
  reason      VARCHAR(255)    NULL,
  changed_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_osh_order (order_id, changed_at),
  CONSTRAINT fk_osh_order FOREIGN KEY (order_id) REFERENCES orders (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 9. INVOICES — gapless, sequential, hash-chained.
--    Deliberately the opposite of anti-forensic: a tamper-evident chain means
--    a missing or altered document is provable. Portuguese law additionally
--    requires AT-certified software and an ATCUD code; see docs/SECURITY.md
--    for what this implementation does and does not satisfy.
-- -----------------------------------------------------------------------------
CREATE TABLE document_series (
  id            BINARY(16)   NOT NULL,
  doc_type      ENUM('invoice','credit_note') NOT NULL,
  series_code   VARCHAR(16)  NOT NULL,   -- 'FT2026'
  year          SMALLINT UNSIGNED NOT NULL,
  next_number   BIGINT UNSIGNED NOT NULL DEFAULT 1,
  atcud_prefix  VARCHAR(16)      NULL,   -- AT-validated series code
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uq_series (doc_type, series_code, year)
) ENGINE=InnoDB;

CREATE TABLE invoices (
  id              BINARY(16)   NOT NULL,
  doc_type        ENUM('invoice','credit_note') NOT NULL DEFAULT 'invoice',
  series_code     VARCHAR(16)  NOT NULL,
  sequence_no     BIGINT UNSIGNED NOT NULL,
  invoice_number  VARCHAR(32)  NOT NULL,   -- FT2026/000148
  atcud           VARCHAR(64)      NULL,
  order_id        BINARY(16)       NULL,
  org_id          BINARY(16)   NOT NULL,
  -- Billing identity is snapshotted: an invoice must render identically in ten
  -- years even if the customer later changes name or address.
  bill_legal_name VARCHAR(255) NOT NULL,
  bill_vat_number VARCHAR(20)      NULL,
  bill_address    TEXT         NOT NULL,
  issue_date      DATE         NOT NULL,
  due_date        DATE         NOT NULL,
  currency        CHAR(3)      NOT NULL DEFAULT 'EUR',
  net_cents       BIGINT       NOT NULL,
  tax_cents       BIGINT       NOT NULL,
  gross_cents     BIGINT       NOT NULL,
  tax_note        VARCHAR(255)     NULL,   -- e.g. 'Reverse charge, Art. 194 VAT Dir.'
  status          ENUM('issued','paid','part_paid','overdue','credited','void')
                               NOT NULL DEFAULT 'issued',
  settled_at      DATETIME(6)      NULL,
  pdf_ref         VARCHAR(255)     NULL,
  -- Tamper-evidence chain
  prev_hash       BINARY(32)       NULL,
  doc_hash        BINARY(32)   NOT NULL,
  created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_invoice_number (invoice_number),
  UNIQUE KEY uq_invoice_seq (doc_type, series_code, sequence_no),
  KEY idx_invoices_org (org_id, issue_date),
  KEY idx_invoices_status (status, due_date),
  KEY idx_invoices_order (order_id),
  CONSTRAINT fk_invoices_org   FOREIGN KEY (org_id) REFERENCES organisations (id),
  CONSTRAINT fk_invoices_order FOREIGN KEY (order_id) REFERENCES orders (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 10. PAYMENTS + WEBHOOK LEDGER
-- -----------------------------------------------------------------------------
CREATE TABLE payments (
  id              BINARY(16)   NOT NULL,
  order_id        BINARY(16)       NULL,
  invoice_id      BINARY(16)       NULL,
  org_id          BINARY(16)   NOT NULL,
  provider        ENUM('mbway','sepa','card','manual','cod') NOT NULL,
  provider_ref    VARCHAR(128)     NULL,   -- PSP transaction id
  direction       ENUM('in','refund') NOT NULL DEFAULT 'in',
  amount_cents    BIGINT       NOT NULL,
  currency        CHAR(3)      NOT NULL DEFAULT 'EUR',
  fee_cents       BIGINT       NOT NULL DEFAULT 0,
  status          ENUM('pending','authorised','settled','failed','refunded')
                               NOT NULL DEFAULT 'pending',
  payer_alias_enc VARBINARY(512)   NULL,   -- MB WAY phone alias: personal data
  reconciled_at   DATETIME(6)      NULL,
  received_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_payment_provider_ref (provider, provider_ref),
  KEY idx_payments_order (order_id),
  KEY idx_payments_invoice (invoice_id),
  KEY idx_payments_org (org_id, received_at),
  CONSTRAINT fk_pay_org     FOREIGN KEY (org_id)     REFERENCES organisations (id),
  CONSTRAINT fk_pay_order   FOREIGN KEY (order_id)   REFERENCES orders (id),
  CONSTRAINT fk_pay_invoice FOREIGN KEY (invoice_id) REFERENCES invoices (id)
) ENGINE=InnoDB;

-- Every inbound webhook is recorded before it is acted on. The UNIQUE on
-- (provider, event_id) is the idempotency guarantee; payload_sha256 detects a
-- replay carrying mutated content under a reused id.
CREATE TABLE webhook_events (
  id             BINARY(16)   NOT NULL,
  provider       VARCHAR(32)  NOT NULL,
  event_id       VARCHAR(128) NOT NULL,
  event_type     VARCHAR(64)      NULL,
  payload_sha256 BINARY(32)   NOT NULL,
  payload_enc    VARBINARY(16384) NULL,   -- retained briefly for dispute forensics
  signature_ok   TINYINT(1)   NOT NULL,
  status         ENUM('received','processed','ignored','failed') NOT NULL DEFAULT 'received',
  attempts       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  last_error     VARCHAR(512)     NULL,
  received_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  processed_at   DATETIME(6)      NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_webhook_event (provider, event_id),
  KEY idx_webhook_status (status, received_at)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 11. ORDER MESSAGING
--    Encrypted at rest. NOT end-to-end encrypted — staff can read these, and
--    the UI says so. Claiming E2EE where a server holds the keys would be a
--    lie to the customer and a misstatement in the privacy notice.
-- -----------------------------------------------------------------------------
CREATE TABLE messages (
  id            BINARY(16)   NOT NULL,
  order_id      BINARY(16)   NOT NULL,
  sender_id     BINARY(16)       NULL,   -- NULL = system message
  sender_side   ENUM('customer','staff','system') NOT NULL,
  body_enc      VARBINARY(8192) NOT NULL,
  attachment_ref VARCHAR(255)    NULL,
  read_at       DATETIME(6)      NULL,
  created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  redacted_at   DATETIME(6)      NULL,
  PRIMARY KEY (id),
  KEY idx_messages_order (order_id, created_at),
  KEY idx_messages_unread (order_id, read_at),
  CONSTRAINT fk_msg_order  FOREIGN KEY (order_id)  REFERENCES orders (id),
  CONSTRAINT fk_msg_sender FOREIGN KEY (sender_id) REFERENCES users (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 12. CREDIT DECISIONS (GDPR Art. 22)
--     Scoring a customer's payment behaviour is legitimate credit risk
--     management. Doing it *automatically* and letting it block orders engages
--     Art. 22, which requires: meaningful information about the logic, human
--     review on request, and the ability to contest. Hence factors_json and
--     the review columns — the score must be explainable, not a black-box
--     blacklist.
-- -----------------------------------------------------------------------------
CREATE TABLE credit_decisions (
  id                 BINARY(16)   NOT NULL,
  org_id             BINARY(16)   NOT NULL,
  decision           ENUM('approve','reduce_limit','require_prepay','hold') NOT NULL,
  is_automated       TINYINT(1)   NOT NULL DEFAULT 1,
  score              SMALLINT         NULL,   -- 0..100
  factors_json       JSON         NOT NULL,   -- the "meaningful information"
  prev_limit_cents   BIGINT           NULL,
  new_limit_cents    BIGINT           NULL,
  effective_from     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  customer_notified_at DATETIME(6)    NULL,
  review_requested_at  DATETIME(6)    NULL,
  reviewed_by        BINARY(16)       NULL,   -- human reviewer
  reviewed_at        DATETIME(6)      NULL,
  review_outcome     ENUM('upheld','overturned','amended') NULL,
  review_notes_enc   VARBINARY(4096)  NULL,
  created_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_credit_org (org_id, effective_from),
  KEY idx_credit_pending_review (review_requested_at, reviewed_at),
  CONSTRAINT fk_credit_org FOREIGN KEY (org_id) REFERENCES organisations (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 13. AUDIT LOG — append-only, and it specifically records PII access.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_log (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  occurred_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  actor_id     BINARY(16)       NULL,
  actor_role   VARCHAR(32)      NULL,
  actor_ip_hash BINARY(32)      NULL,
  action       VARCHAR(64)  NOT NULL,   -- 'pii.read', 'order.accept', 'dsar.export'
  entity_type  VARCHAR(64)      NULL,
  entity_id    BINARY(16)       NULL,
  pii_fields   JSON             NULL,   -- which encrypted fields were decrypted
  metadata     JSON             NULL,
  prev_hash    BINARY(32)       NULL,
  entry_hash   BINARY(32)   NOT NULL,
  PRIMARY KEY (id),
  KEY idx_audit_actor (actor_id, occurred_at),
  KEY idx_audit_entity (entity_type, entity_id, occurred_at),
  KEY idx_audit_action (action, occurred_at)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 14. DATA SUBJECT RIGHTS
-- -----------------------------------------------------------------------------
CREATE TABLE gdpr_requests (
  id                  BINARY(16)   NOT NULL,
  reference           VARCHAR(24)  NOT NULL,   -- DSAR-2026-0031
  subject_user_id     BINARY(16)       NULL,
  subject_email_bidx  BINARY(32)       NULL,   -- for non-users who write in
  request_type        ENUM('access','rectification','erasure','portability',
                           'restriction','objection','art22_review') NOT NULL,
  channel             VARCHAR(32)      NULL,
  status              ENUM('received','identity_pending','in_progress',
                           'fulfilled','partially_refused','refused',
                           'extended') NOT NULL DEFAULT 'received',
  identity_verified_at DATETIME(6)     NULL,
  received_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  due_at              DATETIME(6)  NOT NULL,   -- +1 month (Art. 12(3))
  extended_to         DATETIME(6)      NULL,   -- +2 months if complex
  completed_at        DATETIME(6)      NULL,
  handled_by          BINARY(16)       NULL,
  export_ref          VARCHAR(255)     NULL,
  refusal_ground      VARCHAR(255)     NULL,   -- e.g. Art. 17(3)(b)
  decision_notes_enc  VARBINARY(8192)  NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_dsar_reference (reference),
  KEY idx_dsar_subject (subject_user_id),
  KEY idx_dsar_due (status, due_at),
  CONSTRAINT fk_dsar_user FOREIGN KEY (subject_user_id) REFERENCES users (id)
) ENGINE=InnoDB;

CREATE TABLE consent_records (
  id            BINARY(16)   NOT NULL,
  user_id       BINARY(16)   NOT NULL,
  purpose_code  VARCHAR(64)  NOT NULL,
  granted       TINYINT(1)   NOT NULL,
  notice_version VARCHAR(32) NOT NULL,   -- which privacy notice they saw
  evidence      JSON             NULL,   -- timestamp, ip hash, form version
  granted_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  withdrawn_at  DATETIME(6)      NULL,
  PRIMARY KEY (id),
  KEY idx_consent_user (user_id, purpose_code, granted_at),
  CONSTRAINT fk_consent_user FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB;

CREATE TABLE breach_register (
  id                 BINARY(16)   NOT NULL,
  reference          VARCHAR(24)  NOT NULL,
  detected_at        DATETIME(6)  NOT NULL,
  nature             TEXT         NOT NULL,
  categories_affected JSON            NULL,
  approx_subjects    INT UNSIGNED     NULL,
  likely_consequences TEXT            NULL,
  measures_taken     TEXT             NULL,
  risk_assessment    ENUM('low','medium','high') NOT NULL,
  -- Art. 33: notify the supervisory authority within 72h of becoming aware
  authority_due_at   DATETIME(6)      NULL,
  authority_notified_at DATETIME(6)   NULL,
  subjects_notified_at  DATETIME(6)   NULL,
  not_notified_reason TEXT            NULL,
  closed_at          DATETIME(6)      NULL,
  created_at         DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_breach_ref (reference)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 15. ANALYTICS HELPERS
-- -----------------------------------------------------------------------------
-- Aggregate CRM view. Note it exposes no decrypted PII: the manager dashboard
-- joins this to display names only where the operator has a role that permits
-- it, and every such read is written to audit_log.
CREATE OR REPLACE VIEW v_org_metrics AS
SELECT
  o.id                                   AS org_id,
  o.account_ref,
  o.legal_name,
  o.price_tier,
  o.status,
  o.credit_limit_cents,
  o.payment_terms_days,
  COUNT(DISTINCT ord.id)                 AS orders_total,
  COALESCE(SUM(CASE WHEN ord.status IN ('delivered','closed')
                    THEN ord.gross_cents END), 0)          AS lifetime_gross_cents,
  COALESCE(SUM(CASE WHEN ord.status IN ('delivered','closed')
                    THEN ord.gross_cents - ord.cogs_cents END), 0) AS lifetime_margin_cents,
  MAX(ord.created_at)                    AS last_order_at,
  COALESCE(SUM(CASE WHEN inv.status = 'overdue' THEN inv.gross_cents END), 0)
                                         AS overdue_cents,
  COUNT(DISTINCT CASE WHEN inv.status = 'overdue' THEN inv.id END)
                                         AS overdue_invoices,
  COUNT(DISTINCT CASE WHEN ord.status = 'cancelled' THEN ord.id END)
                                         AS cancelled_orders
FROM organisations o
LEFT JOIN orders   ord ON ord.org_id = o.id
LEFT JOIN invoices inv ON inv.org_id = o.id
GROUP BY o.id;

-- -----------------------------------------------------------------------------
-- 16. ROPA SEED — the retention schedule the purge job actually enforces.
-- -----------------------------------------------------------------------------
INSERT INTO processing_purposes
  (id, code, purpose, lawful_basis, basis_note, data_categories,
   retention_days, retention_note, recipients, transfers_outside_eea)
VALUES
 (UNHEX(REPLACE(UUID(),'-','')), 'account_admin',
  'Operate trade accounts and authenticate authorised users',
  'contract', 'Necessary to perform the supply agreement.',
  JSON_ARRAY('name','business email','business phone','job title'),
  NULL, 'Retained while the account is live; purged 24 months after closure.',
  JSON_ARRAY('internal sales and ops staff'), 0),
 (UNHEX(REPLACE(UUID(),'-','')), 'order_fulfilment',
  'Accept, pick, dispatch and deliver orders',
  'contract', NULL,
  JSON_ARRAY('delivery address','site contact name','site contact phone','access notes'),
  1095, 'Three years after delivery, to cover warranty and dispute windows.',
  JSON_ARRAY('carriers','couriers'), 0),
 (UNHEX(REPLACE(UUID(),'-','')), 'invoicing_tax',
  'Issue invoices and meet statutory accounting and VAT obligations',
  'legal_obligation',
  'PT: 10 years (CIVA / Codigo Comercial). Overrides erasure per Art. 17(3)(b).',
  JSON_ARRAY('billing identity','transaction records'),
  3650, 'Ten fiscal years. Cannot be shortened by an erasure request.',
  JSON_ARRAY('tax authority','statutory auditor'), 0),
 (UNHEX(REPLACE(UUID(),'-','')), 'order_support',
  'Handle customer service enquiries attached to an order',
  'contract', NULL,
  JSON_ARRAY('message content','name'),
  730, 'Two years after the thread closes.',
  JSON_ARRAY('internal support staff'), 0),
 (UNHEX(REPLACE(UUID(),'-','')), 'credit_risk',
  'Assess creditworthiness and set payment terms',
  'legitimate_interest',
  'LIA on file. Art. 22 applies: automated limits are contestable and human-reviewable.',
  JSON_ARRAY('payment history','order history'),
  1825, 'Five years, aligned to the limitation period for debt claims.',
  JSON_ARRAY('internal finance staff'), 0),
 (UNHEX(REPLACE(UUID(),'-','')), 'security_audit',
  'Detect and investigate unauthorised access and data misuse',
  'legal_obligation',
  'Art. 32 security of processing; Art. 33 breach evidence.',
  JSON_ARRAY('hashed IP','user id','access events'),
  365, 'Twelve months of audit trail.',
  JSON_ARRAY('internal security staff','supervisory authority on request'), 0);
