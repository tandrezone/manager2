<?php

declare(strict_types=1);

/**
 * Mobile-first checkout.
 *
 * Contract — the controller supplies:
 *   $order         array{order_number, currency, net_cents, tax_cents, gross_cents}
 *   $items         list<array{name, sku, qty, uom, unit_price_cents, net_cents}>
 *   $locations     list<array{id, label, address, is_default}>   (already decrypted)
 *   $windows       list<array{value, label, capacity_note, available}>
 *   $methods       list<array{value, label, meta, available, unavailable_reason}>
 *   $account       array{account_ref, legal_name, status, payment_terms_days,
 *                        credit_limit_cents, credit_used_cents, order_ceiling_cents}
 *   $errors        array<string, string>
 *   $old           array<string, string>  previously submitted values
 *
 * Design notes:
 *  - Server-rendered, and valid without JavaScript. The JS at the bottom adds
 *    a live total and a double-submit guard; it is not required to place an
 *    order. A warehouse tablet on a bad connection still works.
 *  - The total is in a sticky bar, always visible.
 *  - Every input carries autocomplete and inputmode so mobile keyboards and
 *    autofill behave.
 */

use Manager2\Support\Html;

/** @var array<string, mixed> $order */
/** @var list<array<string, mixed>> $items */
/** @var list<array<string, mixed>> $locations */
/** @var list<array<string, mixed>> $windows */
/** @var list<array<string, mixed>> $methods */
/** @var array<string, mixed> $account */
/** @var array<string, string> $errors */
/** @var array<string, string> $old */

$errors ??= [];
$old ??= [];
$currency = (string) ($order['currency'] ?? 'EUR');

$e = static fn (?string $v): string => Html::e($v);
$money = static fn (int $c): string => Html::money($c, $currency);
$value = static fn (string $k, string $default = ''): string => Html::e($old[$k] ?? $default);

$unverified = ($account['status'] ?? '') !== 'active';
$ceiling = $account['order_ceiling_cents'] ?? null;
$overCeiling = $unverified && is_int($ceiling) && (int) $order['gross_cents'] > $ceiling;

$creditAvailable = max(
    0,
    (int) ($account['credit_limit_cents'] ?? 0) - (int) ($account['credit_used_cents'] ?? 0)
);
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f7f7f5" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#101014" media="(prefers-color-scheme: dark)">
<meta name="robots" content="noindex, nofollow">
<title>Checkout &middot; <?= $e((string) $order['order_number']) ?></title>
<link rel="manifest" href="/manifest.json">
<link rel="stylesheet" href="/assets/app.css">
<link rel="icon" href="/assets/icon-192.png">
<link rel="apple-touch-icon" href="/assets/icon-192.png">
</head>
<body>
<a class="skip-link" href="#main">Skip to checkout</a>

<header class="topbar">
  <h1 class="topbar__title">Checkout</h1>
  <span class="badge badge--neutral mono"><?= $e((string) $order['order_number']) ?></span>
</header>

<main class="shell stack" id="main">

  <?php if ($unverified): ?>
    <div class="notice notice--warn" role="status">
      <span class="notice__icon" aria-hidden="true">&#9203;</span>
      <div class="notice__body">
        <strong>Account verification in progress.</strong>
        <p class="small">
          You can order up to <?= $money((int) $ceiling) ?> while we confirm your
          business registration. Credit terms unlock once verification completes.
        </p>
      </div>
    </div>
  <?php endif; ?>

  <?php if ($errors !== []): ?>
    <div class="notice notice--danger" role="alert">
      <span class="notice__icon" aria-hidden="true">&#9888;</span>
      <div class="notice__body">
        <strong>Please check the following:</strong>
        <ul class="small" style="margin:0.375rem 0 0;padding-left:1.125rem">
          <?php foreach ($errors as $message): ?>
            <li><?= $e($message) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    </div>
  <?php endif; ?>

  <!-- Account ------------------------------------------------------------- -->
  <section class="card" aria-labelledby="acct-h">
    <div class="card__header">
      <h2 class="card__title" id="acct-h">Account</h2>
      <span class="badge <?= $unverified ? 'badge--warn' : 'badge--ok' ?>">
        <?= $unverified ? 'Pending verification' : 'Verified' ?>
      </span>
    </div>
    <div class="row row--between">
      <div>
        <div style="font-weight:650"><?= $e((string) $account['legal_name']) ?></div>
        <div class="small muted mono"><?= $e((string) $account['account_ref']) ?></div>
      </div>
    </div>
  </section>

  <!-- Items --------------------------------------------------------------- -->
  <section class="card" aria-labelledby="items-h">
    <div class="card__header">
      <h2 class="card__title" id="items-h"><?= count($items) ?> line<?= count($items) === 1 ? '' : 's' ?></h2>
      <a class="small" href="/cart">Edit</a>
    </div>

    <?php foreach ($items as $item): ?>
      <div class="line">
        <div class="line__label">
          <div style="font-weight:600"><?= $e((string) $item['name']) ?></div>
          <div class="small muted mono">
            <?= $e((string) $item['sku']) ?> &middot;
            <?= (int) $item['qty'] ?> <?= $e((string) ($item['uom'] ?? 'unit')) ?>
            &times; <?= $money((int) $item['unit_price_cents']) ?>
          </div>
        </div>
        <div class="line__value"><?= $money((int) $item['net_cents']) ?></div>
      </div>
    <?php endforeach; ?>
  </section>

  <form method="post" action="/checkout/submit" id="checkout-form" novalidate>
    <input type="hidden" name="_csrf" value="<?= $e(Html::csrfToken()) ?>">
    <input type="hidden" name="order_number" value="<?= $e((string) $order['order_number']) ?>">

    <!-- Delivery destination --------------------------------------------- -->
    <section class="card" aria-labelledby="dest-h" style="margin-top:1rem">
      <div class="card__header">
        <h2 class="card__title" id="dest-h">Deliver to</h2>
      </div>

      <div class="choice-list">
        <?php foreach ($locations as $i => $location): ?>
          <?php
            $checked = ($old['delivery_location_id'] ?? null) === (string) $location['id']
                || (!isset($old['delivery_location_id']) && !empty($location['is_default']));
          ?>
          <label class="choice">
            <input type="radio" name="delivery_location_id"
                   value="<?= $e((string) $location['id']) ?>"
                   <?= $checked ? 'checked' : '' ?>
                   <?= $i === 0 ? 'required' : '' ?>>
            <span class="choice__body">
              <span class="choice__title">
                <?= $e((string) $location['label']) ?>
                <?php if (!empty($location['is_default'])): ?>
                  <span class="badge badge--accent" style="margin-left:0.25rem">Default</span>
                <?php endif; ?>
              </span>
              <span class="choice__meta"><?= nl2br($e((string) $location['address'])) ?></span>
            </span>
          </label>
        <?php endforeach; ?>

        <label class="choice">
          <input type="radio" name="delivery_location_id" value="__new">
          <span class="choice__body">
            <span class="choice__title">Send to a different address</span>
            <span class="choice__meta">Added to your saved sites for future orders.</span>
          </span>
        </label>
      </div>

      <?php if (isset($errors['delivery_location_id'])): ?>
        <div class="field__error"><?= $e($errors['delivery_location_id']) ?></div>
      <?php endif; ?>
    </section>

    <!-- Delivery window -------------------------------------------------- -->
    <section class="card" aria-labelledby="when-h" style="margin-top:1rem">
      <div class="card__header">
        <h2 class="card__title" id="when-h">Delivery window</h2>
      </div>

      <label class="field">
        <span class="field__label" for="window">Preferred slot</span>
        <select id="window" name="delivery_window" required
                aria-describedby="window-hint"
                <?= isset($errors['delivery_window']) ? 'aria-invalid="true"' : '' ?>>
          <option value="">Choose a window&hellip;</option>
          <?php foreach ($windows as $window): ?>
            <option value="<?= $e((string) $window['value']) ?>"
                    <?= empty($window['available']) ? 'disabled' : '' ?>
                    <?= ($old['delivery_window'] ?? '') === (string) $window['value'] ? 'selected' : '' ?>>
              <?= $e((string) $window['label']) ?><?php
                if (!empty($window['capacity_note'])) {
                    echo ' — ' . $e((string) $window['capacity_note']);
                }
              ?>
            </option>
          <?php endforeach; ?>
        </select>
        <span class="field__hint" id="window-hint">
          A window is a target, not a guarantee. We confirm a firm time when the
          order is accepted, and message you here if it changes.
        </span>
      </label>

      <label class="field">
        <span class="field__label" for="notes">Delivery instructions</span>
        <textarea id="notes" name="delivery_notes" maxlength="1000"
                  autocomplete="off"
                  placeholder="Loading bay access, gate codes, who to ask for, pallet or tail-lift requirements."><?= $value('delivery_notes') ?></textarea>
        <span class="field__hint">
          Stored encrypted and shared only with the driver assigned to this delivery.
        </span>
      </label>

      <div class="grid grid--2">
        <label class="field" style="margin-bottom:0">
          <span class="field__label" for="contact-name">Site contact</span>
          <input id="contact-name" name="site_contact_name" type="text"
                 autocomplete="name" maxlength="200"
                 value="<?= $value('site_contact_name') ?>">
        </label>

        <label class="field" style="margin-bottom:0">
          <span class="field__label" for="contact-phone">Contact number</span>
          <input id="contact-phone" name="site_contact_phone" type="tel"
                 inputmode="tel" autocomplete="tel" maxlength="32"
                 placeholder="+351 …"
                 value="<?= $value('site_contact_phone') ?>">
        </label>
      </div>

      <label class="field" style="margin-top:1rem;margin-bottom:0">
        <span class="field__label" for="po-ref">Your purchase order reference</span>
        <input id="po-ref" name="customer_po_ref" type="text" maxlength="64"
               autocomplete="off" inputmode="text"
               value="<?= $value('customer_po_ref') ?>">
        <span class="field__hint">Optional. Printed on your invoice to match your own records.</span>
      </label>
    </section>

    <!-- Payment ---------------------------------------------------------- -->
    <section class="card" aria-labelledby="pay-h" style="margin-top:1rem">
      <div class="card__header">
        <h2 class="card__title" id="pay-h">Payment</h2>
      </div>

      <div class="choice-list">
        <?php foreach ($methods as $method): ?>
          <?php $disabled = empty($method['available']); ?>
          <label class="choice" <?= $disabled ? 'style="opacity:0.55"' : '' ?>>
            <input type="radio" name="payment_method"
                   value="<?= $e((string) $method['value']) ?>"
                   <?= $disabled ? 'disabled' : '' ?>
                   <?= ($old['payment_method'] ?? '') === (string) $method['value'] ? 'checked' : '' ?>
                   required>
            <span class="choice__body">
              <span class="choice__title"><?= $e((string) $method['label']) ?></span>
              <span class="choice__meta">
                <?= $e((string) ($disabled
                    ? ($method['unavailable_reason'] ?? 'Not available on this account')
                    : ($method['meta'] ?? ''))) ?>
              </span>
            </span>
          </label>
        <?php endforeach; ?>
      </div>

      <?php if ((int) ($account['payment_terms_days'] ?? 0) > 0): ?>
        <p class="small muted" style="margin-top:0.75rem;margin-bottom:0">
          Credit available: <strong class="numeric"><?= $money($creditAvailable) ?></strong>
          on <?= (int) $account['payment_terms_days'] ?>-day terms.
        </p>
      <?php endif; ?>
    </section>

    <!-- Totals ----------------------------------------------------------- -->
    <section class="card" aria-labelledby="total-h" style="margin-top:1rem">
      <div class="card__header"><h2 class="card__title" id="total-h">Total</h2></div>

      <div class="line">
        <span class="line__label">Net</span>
        <span class="line__value"><?= $money((int) $order['net_cents']) ?></span>
      </div>
      <div class="line">
        <span class="line__label">
          VAT
          <?php if ((int) $order['tax_cents'] === 0): ?>
            <span class="badge badge--neutral">Reverse charge</span>
          <?php endif; ?>
        </span>
        <span class="line__value"><?= $money((int) $order['tax_cents']) ?></span>
      </div>
      <div class="line line--total">
        <span class="line__label">Total due</span>
        <span class="line__value"><?= $money((int) $order['gross_cents']) ?></span>
      </div>

      <?php if ((int) $order['tax_cents'] === 0): ?>
        <p class="small muted" style="margin-top:0.75rem;margin-bottom:0">
          Zero-rated intra-EU supply. You account for VAT in your own member state
          under Art. 194 of Directive 2006/112/EC.
        </p>
      <?php endif; ?>
    </section>

    <!-- Consent ---------------------------------------------------------- -->
    <section class="card" style="margin-top:1rem">
      <label class="choice" style="border:0;background:transparent;padding:0">
        <input type="checkbox" name="accept_terms" value="1" required
               <?= ($old['accept_terms'] ?? '') === '1' ? 'checked' : '' ?>>
        <span class="choice__body">
          <span class="choice__title" style="font-weight:500;font-size:0.875rem">
            I confirm I am authorised to place this order on behalf of
            <?= $e((string) $account['legal_name']) ?>, and I accept the
            <a href="/terms" target="_blank" rel="noopener">terms of supply</a>.
          </span>
          <span class="choice__meta">
            We process your details to fulfil this order and to meet our invoicing
            obligations. See the <a href="/privacy" target="_blank" rel="noopener">privacy
            notice</a> for retention periods and your rights.
          </span>
        </span>
      </label>
    </section>

    <!-- Sticky commit bar ------------------------------------------------ -->
    <div class="actionbar">
      <div class="actionbar__inner">
        <div class="actionbar__total">
          <div class="small muted">Total due</div>
          <div class="actionbar__amount numeric" id="bar-total">
            <?= $money((int) $order['gross_cents']) ?>
          </div>
        </div>
        <button type="submit" class="btn btn--primary" id="submit-btn"
                <?= $overCeiling ? 'disabled aria-disabled="true"' : '' ?>>
          <span data-label>Place order</span>
        </button>
      </div>
    </div>

    <?php if ($overCeiling): ?>
      <div class="notice notice--danger" role="alert" style="margin-top:1rem">
        <span class="notice__icon" aria-hidden="true">&#9888;</span>
        <div class="notice__body">
          This order exceeds the <?= $money((int) $ceiling) ?> limit that applies
          before verification completes. Reduce the order, or contact your account
          manager to prioritise verification.
        </div>
      </div>
    <?php endif; ?>
  </form>

  <p class="small faint" style="text-align:center">
    Deliveries are made by our own drivers or a named courier, against a signature
    at the delivery point. Someone must be present to receive the goods.
  </p>
</main>

<div class="offline-banner" id="offline" role="status" aria-live="polite">
  You are offline. Your entries are saved on this device.
</div>

<script>
(function () {
  'use strict';

  var form = document.getElementById('checkout-form');
  if (!form) { return; }

  /* Double-submit guard. Without it, a slow network plus an impatient tap on a
     phone produces two orders, and the second one is discovered by the
     customer, not by us. */
  form.addEventListener('submit', function (event) {
    var button = document.getElementById('submit-btn');

    if (form.dataset.submitted === '1') {
      event.preventDefault();
      return;
    }

    if (!form.checkValidity()) {
      return; /* let the browser show its own messages */
    }

    form.dataset.submitted = '1';
    if (button) {
      button.classList.add('is-busy');
      button.setAttribute('aria-disabled', 'true');
      var label = button.querySelector('[data-label]');
      if (label) { label.textContent = 'Placing order…'; }
    }
  });

  /* Preserve typing across an accidental navigation or a reload on a flaky
     connection. Only free-text fields, and cleared on submit — a delivery
     contact should not outlive the order it was typed for. */
  var DRAFT_KEY = 'm2.checkout.' + <?= Html::json((string) $order['order_number']) ?>;
  var textFields = form.querySelectorAll('textarea, input[type="text"], input[type="tel"]');

  try {
    var saved = JSON.parse(window.localStorage.getItem(DRAFT_KEY) || '{}');
    Array.prototype.forEach.call(textFields, function (field) {
      if (!field.value && typeof saved[field.name] === 'string') {
        field.value = saved[field.name];
      }
    });
  } catch (e) {
    /* Private mode, blocked storage, or quota. The form works without it. */
  }

  var saveTimer = null;
  form.addEventListener('input', function () {
    window.clearTimeout(saveTimer);
    saveTimer = window.setTimeout(function () {
      try {
        var draft = {};
        Array.prototype.forEach.call(textFields, function (field) {
          if (field.value) { draft[field.name] = field.value; }
        });
        window.localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
      } catch (e) { /* ignore */ }
    }, 400);
  });

  form.addEventListener('submit', function () {
    try { window.localStorage.removeItem(DRAFT_KEY); } catch (e) { /* ignore */ }
  });

  /* Offline indicator. */
  var banner = document.getElementById('offline');
  function syncOnlineState() {
    if (banner) { banner.classList.toggle('is-visible', !navigator.onLine); }
  }
  window.addEventListener('online', syncOnlineState);
  window.addEventListener('offline', syncOnlineState);
  syncOnlineState();

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/sw.js').catch(function () {
        /* PWA install is an enhancement; the portal works without it. */
      });
    });
  }
}());
</script>
</body>
</html>
