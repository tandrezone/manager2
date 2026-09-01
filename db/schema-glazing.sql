-- =============================================================================
-- manager2 — made-to-measure glazing extension
--
-- Apply AFTER db/schema.sql.
--
-- WHY THIS FILE EXISTS
-- --------------------
-- The base schema assumes stocked products: a SKU, a quantity, a price, a stock
-- level. Insulating glass units break every one of those assumptions:
--
--   * There is no SKU. A unit is a build-up + a coating + a tint + a spacer +
--     two dimensions in millimetres, configured per line.
--   * There is no stock. There is fabrication lead time and weekly capacity.
--   * Price is per square metre with a MINIMUM BILLABLE AREA per unit, so a
--     300x400 unit and a 600x900 unit can cost the same.
--   * The performance figures (Ug, g-value, light transmittance, Rw) are part of
--     the product — they are what the architect specified and what the customer
--     is actually buying.
--   * The goods are non-returnable. A unit cut to the wrong size is scrap, which
--     changes both the data-capture stakes and the payment terms.
--   * CE marking under the Construction Products Regulation applies (EN 1279-5),
--     which brings a ten-year duty to identify who you supplied — see §5 of
--     docs/OVERVIEW.md and the dop_records table below.
--
-- Nothing in the encryption, invoicing, audit or GDPR layers needs to change.
-- =============================================================================

USE manager2;

-- -----------------------------------------------------------------------------
-- 1. GLASS BUILD-UPS
--    The base product: a pane/cavity/pane construction, notated the way the
--    trade writes it — '4-16Ar-4' is 4 mm glass, 16 mm argon-filled cavity,
--    4 mm glass.
-- -----------------------------------------------------------------------------
CREATE TABLE glass_specs (
  id                  BINARY(16)   NOT NULL,
  code                VARCHAR(32)  NOT NULL,   -- '4-16Ar-4'
  name                VARCHAR(160) NOT NULL,
  family              ENUM('double','triple','single','laminated_only') NOT NULL
                                   DEFAULT 'double',
  -- Construction, in millimetres. Outer is the face exposed to the weather.
  pane_outer_mm       DECIMAL(4,1) NOT NULL,
  cavity_1_mm         DECIMAL(4,1)     NULL,
  pane_middle_mm      DECIMAL(4,1)     NULL,   -- triple glazing only
  cavity_2_mm         DECIMAL(4,1)     NULL,
  pane_inner_mm       DECIMAL(4,1) NOT NULL,
  gas_fill            ENUM('air','argon','krypton') NOT NULL DEFAULT 'argon',
  -- EN 1279-3 sets the gas concentration tolerance. Recording the declared
  -- figure is what lets a Declaration of Performance be produced later.
  gas_concentration_pct DECIMAL(4,1)   NULL,
  coating             ENUM('none','low_e_soft','low_e_hard','solar_control')
                                   NOT NULL DEFAULT 'none',
  coating_surface     TINYINT UNSIGNED NULL,   -- surface #2 is the usual position

  -- Declared performance. These are the numbers that go on the DoP, so they are
  -- stored per build-up rather than computed: a computed U-value is an estimate,
  -- and a declared one has test evidence behind it.
  ug_w_m2k            DECIMAL(4,2)     NULL,   -- thermal transmittance
  g_value             DECIMAL(4,3)     NULL,   -- solar factor (0..1)
  light_transmittance DECIMAL(4,3)     NULL,   -- LT (0..1)
  rw_db               TINYINT UNSIGNED NULL,   -- weighted sound reduction

  -- Commercial
  rate_cents_per_m2   BIGINT       NOT NULL,   -- base rate, standard tier
  min_billable_m2     DECIMAL(6,3) NOT NULL DEFAULT 0.650,
  lead_time_days      SMALLINT UNSIGNED NOT NULL DEFAULT 5,

  -- Production limits. Enforced at order entry, so an unmakeable unit is
  -- rejected on the screen rather than discovered at the cutting table.
  max_width_mm        INT UNSIGNED NOT NULL DEFAULT 3210,
  max_height_mm       INT UNSIGNED NOT NULL DEFAULT 2250,
  min_width_mm        INT UNSIGNED NOT NULL DEFAULT 300,
  min_height_mm       INT UNSIGNED NOT NULL DEFAULT 300,
  max_area_m2         DECIMAL(6,3)     NULL,
  size_increment_mm   TINYINT UNSIGNED NOT NULL DEFAULT 1,

  -- Standard the CE marking is declared against.
  harmonised_standard VARCHAR(32)  NOT NULL DEFAULT 'EN 1279-5',
  unit_cost_cents_per_m2 BIGINT    NOT NULL DEFAULT 0,   -- for margin analytics
  is_active           TINYINT(1)   NOT NULL DEFAULT 1,
  created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                   ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_glass_spec_code (code),
  KEY idx_glass_active (is_active, family)
) ENGINE=InnoDB;

-- Tier pricing per build-up, mirroring product_prices in the base schema.
CREATE TABLE glass_spec_prices (
  id                BINARY(16)   NOT NULL,
  spec_id           BINARY(16)   NOT NULL,
  price_tier        ENUM('standard','volume','key_account') NOT NULL,
  min_m2            DECIMAL(8,3) NOT NULL DEFAULT 0.000,  -- volume break
  rate_cents_per_m2 BIGINT       NOT NULL,
  valid_from        DATE             NULL,
  valid_to          DATE             NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_glass_price_break (spec_id, price_tier, min_m2, valid_from),
  CONSTRAINT fk_gsp_spec FOREIGN KEY (spec_id) REFERENCES glass_specs (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 2. OPTIONS
--    Tints, toughening, lamination, spacer type, acoustic interlayers. Modelled
--    as multiplicative/additive modifiers rather than as separate build-ups,
--    because otherwise the catalogue is a combinatorial explosion.
-- -----------------------------------------------------------------------------
CREATE TABLE glass_options (
  id                  BINARY(16)   NOT NULL,
  code                VARCHAR(32)  NOT NULL,   -- 'TINT_SMOKE_GREY'
  name                VARCHAR(160) NOT NULL,
  option_group        ENUM('tint','safety','spacer','acoustic','edgework','other')
                                   NOT NULL,
  -- Options in the same group are mutually exclusive where this is set: a unit
  -- has one tint, not three.
  exclusive_in_group  TINYINT(1)   NOT NULL DEFAULT 1,
  applies_to_pane     ENUM('outer','inner','middle','unit') NOT NULL DEFAULT 'outer',

  uplift_cents_per_m2 BIGINT       NOT NULL DEFAULT 0,
  uplift_cents_flat   BIGINT       NOT NULL DEFAULT 0,   -- per unit, not per m2
  lead_time_add_days  SMALLINT     NOT NULL DEFAULT 0,
  cost_cents_per_m2   BIGINT       NOT NULL DEFAULT 0,

  -- Performance modifiers. Multipliers for optical properties, deltas for the
  -- rest. NULL means "leaves this property alone".
  g_value_factor      DECIMAL(5,3)     NULL,
  lt_factor           DECIMAL(5,3)     NULL,
  ug_delta            DECIMAL(4,2)     NULL,
  rw_delta            TINYINT          NULL,

  -- Presentation: the tint colour, so the configurator can render the unit.
  render_hex          CHAR(7)          NULL,
  render_opacity      DECIMAL(3,2)     NULL,

  -- Size limits can tighten with the option — a toughening oven is smaller than
  -- a cutting table, and this is a classic source of accepted-but-unmakeable
  -- orders.
  max_width_mm        INT UNSIGNED     NULL,
  max_height_mm       INT UNSIGNED     NULL,
  max_area_m2         DECIMAL(6,3)     NULL,

  requires_handling_equipment TINYINT(1) NOT NULL DEFAULT 0,
  is_active           TINYINT(1)   NOT NULL DEFAULT 1,
  sort_order          SMALLINT     NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uq_glass_option_code (code),
  KEY idx_option_group (option_group, is_active, sort_order)
) ENGINE=InnoDB;

-- Options a build-up will not accept (e.g. no toughening on a laminated inner).
CREATE TABLE glass_spec_option_exclusions (
  spec_id   BINARY(16) NOT NULL,
  option_id BINARY(16) NOT NULL,
  reason    VARCHAR(255) NULL,
  PRIMARY KEY (spec_id, option_id),
  CONSTRAINT fk_gsoe_spec   FOREIGN KEY (spec_id)   REFERENCES glass_specs (id),
  CONSTRAINT fk_gsoe_option FOREIGN KEY (option_id) REFERENCES glass_options (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 3. ORDER LINES BECOME CONFIGURED UNITS
--    order_items keeps its money columns; these add the configuration. Every
--    figure is snapshotted, because a rate card change must never retroactively
--    alter what a customer was quoted and charged.
-- -----------------------------------------------------------------------------
ALTER TABLE order_items
  ADD COLUMN spec_id             BINARY(16)   NULL AFTER product_id,
  ADD COLUMN spec_code_snapshot  VARCHAR(32)  NULL AFTER sku_snapshot,
  ADD COLUMN width_mm            INT UNSIGNED NULL AFTER name_snapshot,
  ADD COLUMN height_mm           INT UNSIGNED NULL AFTER width_mm,
  -- Actual area vs billable area. Storing both is what lets the portal answer
  -- "why am I paying for 0.65 m2 when the unit is 0.12 m2" without a phone call.
  ADD COLUMN area_m2             DECIMAL(8,4) NULL AFTER height_mm,
  ADD COLUMN billable_m2         DECIMAL(8,4) NULL AFTER area_m2,
  ADD COLUMN rate_cents_per_m2   BIGINT       NULL AFTER billable_m2,
  ADD COLUMN options_json        JSON         NULL AFTER rate_cents_per_m2,
  ADD COLUMN options_uplift_cents BIGINT      NOT NULL DEFAULT 0 AFTER options_json,
  -- Declared performance as quoted, snapshotted for the DoP and for any later
  -- dispute about what was specified.
  ADD COLUMN ug_w_m2k            DECIMAL(4,2) NULL AFTER options_uplift_cents,
  ADD COLUMN g_value             DECIMAL(4,3) NULL AFTER ug_w_m2k,
  ADD COLUMN light_transmittance DECIMAL(4,3) NULL AFTER g_value,
  ADD COLUMN rw_db               TINYINT UNSIGNED NULL AFTER light_transmittance,
  -- Who is responsible for the measurement. This single column decides who pays
  -- for a remake, and it is the most argued-about fact in the whole trade.
  ADD COLUMN measured_by         ENUM('customer','our_surveyor','architect_drawing')
                                 NOT NULL DEFAULT 'customer' AFTER rw_db,
  ADD COLUMN position_ref        VARCHAR(64)  NULL AFTER measured_by,  -- 'Plot 12 / W03'
  ADD COLUMN lead_time_days      SMALLINT UNSIGNED NULL AFTER position_ref,
  ADD CONSTRAINT fk_items_spec FOREIGN KEY (spec_id) REFERENCES glass_specs (id);

CREATE INDEX idx_items_spec ON order_items (spec_id);
CREATE INDEX idx_items_position ON order_items (order_id, position_ref);

-- Orders gain a production view.
ALTER TABLE orders
  ADD COLUMN total_m2            DECIMAL(10,3) NOT NULL DEFAULT 0 AFTER cogs_cents,
  ADD COLUMN production_week     CHAR(8)       NULL AFTER promised_at,  -- '2026-W36'
  ADD COLUMN production_status   ENUM('not_scheduled','scheduled','cutting',
                                      'sealing','curing','ready','shipped')
                                 NOT NULL DEFAULT 'not_scheduled' AFTER production_week,
  ADD COLUMN handling_equipment  ENUM('none','a_frame','stillage','tail_lift',
                                      'crane','two_person')
                                 NOT NULL DEFAULT 'a_frame' AFTER dispatch_method;

CREATE INDEX idx_orders_production ON orders (production_week, production_status);

-- -----------------------------------------------------------------------------
-- 4. PRODUCTION CAPACITY
--    Square metres per week per line. The number that answers "can we take this
--    rush order" — currently answered by intuition in most plants.
-- -----------------------------------------------------------------------------
CREATE TABLE production_lines (
  id             BINARY(16)   NOT NULL,
  code           VARCHAR(32)  NOT NULL,
  name           VARCHAR(120) NOT NULL,
  capacity_m2_per_week DECIMAL(10,2) NOT NULL,
  handles_triple TINYINT(1)   NOT NULL DEFAULT 0,
  max_width_mm   INT UNSIGNED NOT NULL DEFAULT 3210,
  max_height_mm  INT UNSIGNED NOT NULL DEFAULT 2250,
  is_active      TINYINT(1)   NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uq_line_code (code)
) ENGINE=InnoDB;

CREATE TABLE production_capacity (
  id              BINARY(16)   NOT NULL,
  line_id         BINARY(16)   NOT NULL,
  week            CHAR(8)      NOT NULL,   -- ISO week, '2026-W36'
  capacity_m2     DECIMAL(10,2) NOT NULL,  -- may differ from nominal: holidays
  committed_m2    DECIMAL(10,2) NOT NULL DEFAULT 0,
  note            VARCHAR(255)     NULL,   -- 'August shutdown, one shift'
  PRIMARY KEY (id),
  UNIQUE KEY uq_capacity_week (line_id, week),
  CONSTRAINT fk_cap_line FOREIGN KEY (line_id) REFERENCES production_lines (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 5. REMAKES
--    Breakage, unit failure, wrong size. A real and recurring workflow, and the
--    fault column is what decides who absorbs the cost.
-- -----------------------------------------------------------------------------
CREATE TABLE remakes (
  id                 BINARY(16)   NOT NULL,
  original_item_id   BINARY(16)   NOT NULL,
  replacement_item_id BINARY(16)      NULL,   -- set once the remake is ordered
  org_id             BINARY(16)   NOT NULL,
  reason             ENUM('transit_damage','seal_failure','wrong_size',
                          'wrong_specification','site_damage','visual_defect',
                          'other') NOT NULL,
  fault              ENUM('manufacturer','customer','carrier','shared','undetermined')
                                  NOT NULL DEFAULT 'undetermined',
  chargeable         TINYINT(1)   NOT NULL DEFAULT 0,
  reported_at        DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  reported_by        BINARY(16)       NULL,
  -- Photographs are evidence in a carrier claim, and they can show a site and
  -- the people on it, so they are referenced rather than inlined and the
  -- reference points at access-controlled storage.
  evidence_ref       VARCHAR(255)     NULL,
  notes_enc          VARBINARY(4096)  NULL,
  resolved_at        DATETIME(6)      NULL,
  resolved_by        BINARY(16)       NULL,
  credit_note_id     BINARY(16)       NULL,
  cost_cents         BIGINT       NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY idx_remakes_org (org_id, reported_at),
  KEY idx_remakes_fault (fault, reported_at),
  KEY idx_remakes_open (resolved_at),
  CONSTRAINT fk_remake_item     FOREIGN KEY (original_item_id) REFERENCES order_items (id),
  CONSTRAINT fk_remake_repl     FOREIGN KEY (replacement_item_id) REFERENCES order_items (id),
  CONSTRAINT fk_remake_org      FOREIGN KEY (org_id) REFERENCES organisations (id),
  CONSTRAINT fk_remake_credit   FOREIGN KEY (credit_note_id) REFERENCES invoices (id)
) ENGINE=InnoDB;

-- -----------------------------------------------------------------------------
-- 6. CE MARKING AND TRACEABILITY (Construction Products Regulation)
--
--    CPR Art. 11(4): units must carry type, batch or serial identification.
--    CPR Art. 11(2): keep the DoP and technical documentation for 10 years after
--                    the product is placed on the market.
--    CPR Art. 16:    for 10 years, on request, identify the suppliers who
--                    supplied you AND the customers you supplied.
--
--    That last duty is why this system is built around identified trade accounts.
--    The join from dop_records through order_items to organisations IS the
--    Art. 16 customer-side record, and it is a query rather than an afternoon in
--    the filing room.
-- -----------------------------------------------------------------------------
CREATE TABLE dop_records (
  id                  BINARY(16)   NOT NULL,
  dop_number          VARCHAR(64)  NOT NULL,   -- 'DoP-2026-00418'
  spec_id             BINARY(16)   NOT NULL,
  batch_ref           VARCHAR(64)  NOT NULL,   -- marked on the unit or spacer
  harmonised_standard VARCHAR(32)  NOT NULL DEFAULT 'EN 1279-5',
  system_of_avcp      VARCHAR(16)  NOT NULL DEFAULT '3',
  notified_body       VARCHAR(120)     NULL,
  declared_performance JSON        NOT NULL,   -- Ug, g, LT, Rw as declared
  -- 'Placed on the market' starts the ten-year clock in Art. 11(2).
  placed_on_market_at DATE         NOT NULL,
  retain_until        DATE         NOT NULL,   -- placed_on_market_at + 10 years
  document_ref        VARCHAR(255)     NULL,   -- PDF in access-controlled storage
  document_sha256     BINARY(32)       NULL,
  language            CHAR(2)      NOT NULL DEFAULT 'pt',  -- Art. 7: language of the member state
  created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  UNIQUE KEY uq_dop_number (dop_number),
  KEY idx_dop_batch (batch_ref),
  KEY idx_dop_retention (retain_until),
  CONSTRAINT fk_dop_spec FOREIGN KEY (spec_id) REFERENCES glass_specs (id)
) ENGINE=InnoDB;

-- Which units were supplied under which declaration, and therefore to whom.
CREATE TABLE unit_traceability (
  id              BINARY(16)   NOT NULL,
  order_item_id   BINARY(16)   NOT NULL,
  dop_record_id   BINARY(16)   NOT NULL,
  unit_serial     VARCHAR(64)  NOT NULL,   -- per-unit mark
  produced_at     DATETIME(6)      NULL,
  line_id         BINARY(16)       NULL,
  supplied_at     DATETIME(6)      NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_unit_serial (unit_serial),
  KEY idx_trace_item (order_item_id),
  KEY idx_trace_dop (dop_record_id),
  CONSTRAINT fk_trace_item FOREIGN KEY (order_item_id) REFERENCES order_items (id),
  CONSTRAINT fk_trace_dop  FOREIGN KEY (dop_record_id) REFERENCES dop_records (id),
  CONSTRAINT fk_trace_line FOREIGN KEY (line_id) REFERENCES production_lines (id)
) ENGINE=InnoDB;

-- The Art. 16 answer, as one query. Given a batch or a serial, who received it.
CREATE OR REPLACE VIEW v_cpr_supply_record AS
SELECT
  d.dop_number,
  d.batch_ref,
  t.unit_serial,
  gs.code                AS build_up,
  d.harmonised_standard,
  d.placed_on_market_at,
  d.retain_until,
  o.order_number,
  o.dispatched_at,
  g.account_ref,
  g.legal_name           AS supplied_to,
  g.vat_number           AS supplied_to_vat,
  g.registered_address   AS supplied_to_address,
  oi.width_mm,
  oi.height_mm,
  oi.ug_w_m2k,
  oi.g_value,
  oi.rw_db
FROM unit_traceability t
JOIN dop_records  d  ON d.id  = t.dop_record_id
JOIN order_items  oi ON oi.id = t.order_item_id
JOIN orders       o  ON o.id  = oi.order_id
JOIN organisations g ON g.id  = o.org_id
JOIN glass_specs  gs ON gs.id = d.spec_id;

-- -----------------------------------------------------------------------------
-- 7. ANALYTICS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_production_load AS
SELECT
  o.production_week          AS week,
  SUM(o.total_m2)            AS committed_m2,
  COUNT(*)                   AS order_count,
  SUM(o.gross_cents)         AS gross_cents,
  SUM(o.gross_cents - o.cogs_cents) AS margin_cents
FROM orders o
WHERE o.production_week IS NOT NULL
  AND o.status NOT IN ('draft','declined','cancelled')
GROUP BY o.production_week;

-- Margin by build-up: which products are actually paying for the plant.
CREATE OR REPLACE VIEW v_margin_by_spec AS
SELECT
  gs.code,
  gs.name,
  gs.family,
  COUNT(DISTINCT oi.order_id)            AS orders,
  SUM(oi.qty)                            AS units,
  SUM(oi.billable_m2 * oi.qty)           AS billable_m2,
  SUM(oi.net_cents)                      AS net_cents,
  SUM(oi.net_cents - (oi.unit_cost_cents * oi.qty)) AS margin_cents,
  CASE WHEN SUM(oi.net_cents) > 0
       THEN ROUND(100 * SUM(oi.net_cents - (oi.unit_cost_cents * oi.qty))
                      / SUM(oi.net_cents), 1)
       ELSE NULL END                     AS margin_pct
FROM order_items oi
JOIN glass_specs gs ON gs.id = oi.spec_id
JOIN orders o       ON o.id  = oi.order_id
WHERE o.status IN ('accepted','picking','dispatched','delivered','closed')
GROUP BY gs.id;

-- Remake rate by fault. If the manufacturer-fault line is climbing, something in
-- the plant is wrong; if the customer-fault line is climbing, site measuring is.
CREATE OR REPLACE VIEW v_remake_rate AS
SELECT
  DATE_FORMAT(r.reported_at, '%Y-%m') AS month,
  r.fault,
  COUNT(*)                            AS remakes,
  SUM(r.cost_cents)                   AS cost_cents
FROM remakes r
GROUP BY month, r.fault;

-- -----------------------------------------------------------------------------
-- 8. RETENTION
--    CE documentation retention is its own purpose with its own ten-year clock,
--    so RetentionPurger never treats it as expired order data.
-- -----------------------------------------------------------------------------
INSERT INTO processing_purposes
  (id, code, purpose, lawful_basis, basis_note, data_categories,
   retention_days, retention_note, recipients, transfers_outside_eea)
VALUES
 (UNHEX(REPLACE(UUID(),'-','')), 'cpr_traceability',
  'Maintain CE marking documentation and supply-chain traceability for construction products',
  'legal_obligation',
  CONCAT('CPR Arts. 11(2), 11(4) and 16: keep the declaration of performance and ',
         'technical documentation for 10 years, and be able to identify on request ',
         'both suppliers and the customers supplied.'),
  JSON_ARRAY('trade account identity','delivery record','unit serial'),
  3650,
  CONCAT('Ten years from placing on the market. Cannot be shortened by an erasure ',
         'request — the identity of the customer supplied IS the record the ',
         'regulation requires.'),
  JSON_ARRAY('market surveillance authority on request','notified body'), 0)
ON DUPLICATE KEY UPDATE purpose = VALUES(purpose);
