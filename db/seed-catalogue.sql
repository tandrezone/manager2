-- =============================================================================
-- manager2 — simplified catalogue: clear and smoked glass, cut to size
--
-- Apply AFTER db/schema.sql and db/schema-glazing.sql.
--
-- The whole price list is: two products, five thicknesses, one rate per square
-- metre, a minimum billable area, and a lead time that follows thickness.
-- Everything the order form needs is in these two tables.
-- =============================================================================

USE manager2;

-- Single glazing has ONE pane, so the inner-pane column must be nullable.
-- The glazing schema was written for insulating units, where both panes exist.
ALTER TABLE glass_specs MODIFY pane_inner_mm DECIMAL(4,1) NULL;

DELETE FROM glass_spec_option_exclusions;
DELETE FROM glass_spec_prices;
DELETE FROM glass_options;
DELETE FROM glass_specs;

-- -----------------------------------------------------------------------------
-- Clear float glass, by thickness. Rates are illustrative — replace with the
-- workshop's own rate card.
--
-- min_billable_m2 = 0.25: a 300 x 400 offcut costs the same as a 500 x 500 one,
-- because the cutting, edging and handling time barely differ. Customers query
-- this constantly, which is why the order form shows billed area next to actual
-- area rather than burying it.
-- -----------------------------------------------------------------------------
INSERT INTO glass_specs
  (id, code, name, family, pane_outer_mm, pane_inner_mm, gas_fill, coating,
   rate_cents_per_m2, unit_cost_cents_per_m2, min_billable_m2, lead_time_days,
   max_width_mm, max_height_mm, min_width_mm, min_height_mm,
   harmonised_standard, is_active)
VALUES
  (UNHEX(REPLACE(UUID(),'-','')), 'S4',  'Vidro simples 4 mm',  'single', 4.0,  NULL, 'air', 'none',
   2800, 1650, 0.250, 2, 2400, 1600, 100, 100, 'EN 572-9', 1),
  (UNHEX(REPLACE(UUID(),'-','')), 'S5',  'Vidro simples 5 mm',  'single', 5.0,  NULL, 'air', 'none',
   3400, 2000, 0.250, 2, 2400, 1600, 100, 100, 'EN 572-9', 1),
  (UNHEX(REPLACE(UUID(),'-','')), 'S6',  'Vidro simples 6 mm',  'single', 6.0,  NULL, 'air', 'none',
   4100, 2450, 0.250, 2, 2400, 1600, 100, 100, 'EN 572-9', 1),
  (UNHEX(REPLACE(UUID(),'-','')), 'S8',  'Vidro simples 8 mm',  'single', 8.0,  NULL, 'air', 'none',
   5800, 3500, 0.250, 3, 2400, 1600, 100, 100, 'EN 572-9', 1),
  (UNHEX(REPLACE(UUID(),'-','')), 'S10', 'Vidro simples 10 mm', 'single', 10.0, NULL, 'air', 'none',
   7600, 4600, 0.250, 3, 2400, 1600, 100, 100, 'EN 572-9', 1);

-- -----------------------------------------------------------------------------
-- Smoked glass is the same base product with a body tint, so it is an option
-- rather than five more rows. One uplift per square metre, applied on top of
-- whichever thickness the customer picked.
-- -----------------------------------------------------------------------------
INSERT INTO glass_options
  (id, code, name, option_group, exclusive_in_group, applies_to_pane,
   uplift_cents_per_m2, cost_cents_per_m2, lead_time_add_days,
   g_value_factor, lt_factor, render_hex, render_opacity, is_active, sort_order)
VALUES
  (UNHEX(REPLACE(UUID(),'-','')), 'TINT_CLEAR', 'Incolor', 'tint', 1, 'outer',
   0, 0, 0, 1.000, 1.000, NULL, NULL, 1, 1),
  (UNHEX(REPLACE(UUID(),'-','')), 'TINT_SMOKE', 'Fumado cinza', 'tint', 1, 'outer',
   1600, 950, 0, 0.480, 0.360, '#5A5F63', 0.62, 1, 2);

-- -----------------------------------------------------------------------------
-- Trade discount. A regular glazier does not pay the walk-in rate.
-- -----------------------------------------------------------------------------
INSERT INTO glass_spec_prices (id, spec_id, price_tier, min_m2, rate_cents_per_m2)
SELECT UNHEX(REPLACE(UUID(),'-','')), s.id, 'volume', 0.000,
       ROUND(s.rate_cents_per_m2 * 0.90)
  FROM glass_specs s;

INSERT INTO glass_spec_prices (id, spec_id, price_tier, min_m2, rate_cents_per_m2)
SELECT UNHEX(REPLACE(UUID(),'-','')), s.id, 'key_account', 0.000,
       ROUND(s.rate_cents_per_m2 * 0.84)
  FROM glass_specs s;

-- -----------------------------------------------------------------------------
-- One van, one cutting bench.
-- -----------------------------------------------------------------------------
DELETE FROM production_capacity;
DELETE FROM production_lines;

INSERT INTO production_lines
  (id, code, name, capacity_m2_per_week, handles_triple, max_width_mm, max_height_mm, is_active)
VALUES (UNHEX(REPLACE(UUID(),'-','')), 'BANCA1', 'Banca de corte', 70.00, 0, 2400, 1600, 1);

SELECT code, name, ROUND(rate_cents_per_m2 / 100, 2) AS eur_m2,
       min_billable_m2, lead_time_days
  FROM glass_specs ORDER BY pane_outer_mm;
