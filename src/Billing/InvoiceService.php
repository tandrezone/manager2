<?php

declare(strict_types=1);

namespace Manager2\Billing;

use Manager2\Audit\AuditLog;
use Manager2\Auth\VatNumber;
use Manager2\Support\Uuid;
use PDO;

/**
 * Invoice issuance: gapless sequential numbering with a tamper-evident chain.
 *
 * This class is where the system's stance is clearest. A hash-chained,
 * gap-checked, permanently retained document series is the *opposite* of
 * anti-forensic design: it exists so that a missing or altered invoice is
 * provable, by the tax authority, by an auditor, and by the customer.
 *
 * Numbering
 * ---------
 * EU invoicing rules (VAT Directive Art. 226(2)) require a sequential number
 * that uniquely identifies the invoice. "Sequential" means no gaps: a gap is
 * read as a suppressed sale. So the number is allocated under a row lock, in a
 * short transaction, at the moment of issue — never reserved earlier and never
 * derived from an auto-increment, which skips values on rollback.
 *
 * The consequence: allocation must be the *last* fallible step. Do not allocate
 * a number and then call a PDF renderer or an email service inside the same
 * transaction; if that fails you have burned a number. Issue, commit, then
 * render asynchronously from the stored row.
 *
 * Chaining
 * --------
 *   doc_hash = SHA256(prev_hash || canonical_document_string)
 *
 * Altering any issued invoice breaks verification for every later document in
 * the series. `verifySeries()` walks the chain and also asserts the sequence has
 * no holes.
 *
 * Portugal, specifically
 * ---------------------
 * This is a correct foundation, not a certified solution. Portuguese law
 * (Portaria 195/2020, and the SAF-T/ATCUD regime) requires invoicing software
 * *certified by the Autoridade Tributária*, with documents signed by an
 * RSA-2048 private key registered with the AT, an ATCUD code derived from an
 * AT-issued series validation code, and a QR code on the printed document.
 * SHA-256 chaining does not substitute for any of that. Before issuing a real
 * invoice in Portugal you need:
 *
 *   - AT software certification (or an already-certified issuer as a service);
 *   - the AT-validated series code, stored in `document_series.atcud_prefix`;
 *   - RSA signing of the canonical string per the Portaria, alongside this hash;
 *   - monthly SAF-T (PT) export.
 *
 * Treat `signDocument()` as the hook where the AT-compliant RSA signature goes.
 * Do not ship this to a Portuguese production environment without a tax adviser
 * confirming the certification route.
 */
final class InvoiceService
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly AuditLog $audit
    ) {
    }

    /**
     * Issue an invoice for a paid or credit-terms order.
     *
     * Idempotent per order: an order that already has a live invoice returns the
     * existing one rather than issuing a second. Webhook retries reach this
     * method, and a duplicate invoice is worse than a missing one — it has to be
     * credited, which means two more documents.
     *
     * @return array{invoice_id:string, invoice_number:string, created:bool}
     */
    public function issueForOrder(string $orderId, ?string $actorId = null): array
    {
        $existing = $this->pdo->prepare(
            "SELECT id, invoice_number FROM invoices
              WHERE order_id = ? AND doc_type = 'invoice' AND status <> 'void'
              LIMIT 1"
        );
        $existing->execute([$orderId]);

        if ($row = $existing->fetch()) {
            return [
                'invoice_id' => Uuid::toString((string) $row['id']),
                'invoice_number' => (string) $row['invoice_number'],
                'created' => false,
            ];
        }

        if ($this->pdo->inTransaction()) {
            throw new \LogicException(
                'issueForOrder() opens its own short transaction; do not nest it inside a '
                . 'longer one, or a slow sibling operation will hold the numbering lock.'
            );
        }

        $this->pdo->beginTransaction();

        try {
            $order = $this->loadOrderForInvoicing($orderId);
            $series = $this->lockSeries('invoice', (int) date('Y'));

            $sequenceNo = (int) $series['next_number'];
            $invoiceNumber = sprintf('%s/%06d', $series['series_code'], $sequenceNo);
            $invoiceId = Uuid::v7();

            $issueDate = new \DateTimeImmutable('today');
            $dueDate = $issueDate->add(
                new \DateInterval('P' . max(0, (int) $order['payment_terms_days']) . 'D')
            );

            // Reverse charge: an intra-EU supply to a VAT-registered business in
            // another member state is zero-rated, with the buyer accounting for
            // the tax. This is exactly why the VAT number had to be verified at
            // onboarding rather than merely collected.
            $taxNote = null;
            if ((int) $order['tax_exempt'] === 1 && $order['vat_number'] !== null) {
                $taxNote = 'Reverse charge — VAT to be accounted for by the recipient '
                    . '(Art. 194 Directive 2006/112/EC).';
            }

            $prevHash = $this->seriesHead('invoice', (string) $series['series_code']);

            $canonical = $this->canonicalDocumentString([
                'number' => $invoiceNumber,
                'issue_date' => $issueDate->format('Y-m-d'),
                'vat' => (string) ($order['vat_number'] ?? ''),
                'legal_name' => (string) $order['legal_name'],
                'net' => (int) $order['net_cents'],
                'tax' => (int) $order['tax_cents'],
                'gross' => (int) $order['gross_cents'],
                'currency' => (string) $order['currency'],
            ]);

            $docHash = hash('sha256', ($prevHash ?? '') . $canonical, true);

            $alreadyPaid = (string) $order['payment_status'] === 'paid';

            $insert = $this->pdo->prepare(
                'INSERT INTO invoices
                    (id, doc_type, series_code, sequence_no, invoice_number, atcud,
                     order_id, org_id, bill_legal_name, bill_vat_number, bill_address,
                     issue_date, due_date, currency, net_cents, tax_cents, gross_cents,
                     tax_note, status, settled_at, prev_hash, doc_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $insert->execute([
                $invoiceId,
                'invoice',
                $series['series_code'],
                $sequenceNo,
                $invoiceNumber,
                $this->atcud($series['atcud_prefix'] ?? null, $sequenceNo),
                $orderId,
                $order['org_id'],
                $order['legal_name'],
                $order['vat_number'],
                (string) ($order['registered_address'] ?? '(address on file)'),
                $issueDate->format('Y-m-d'),
                $dueDate->format('Y-m-d'),
                $order['currency'],
                (int) $order['net_cents'],
                (int) $order['tax_cents'],
                (int) $order['gross_cents'],
                $taxNote,
                $alreadyPaid ? 'paid' : 'issued',
                // settled_at must be populated, not just the status: it is the
                // only record of WHEN payment landed, and the credit scorer
                // measures days-late from it. Leaving it null made every
                // prepaid invoice look unsettled forever.
                $alreadyPaid ? (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
                    ->format('Y-m-d H:i:s.u') : null,
                $prevHash,
                $docHash,
            ]);

            $bump = $this->pdo->prepare(
                'UPDATE document_series SET next_number = next_number + 1 WHERE id = ?'
            );
            $bump->execute([$series['id']]);

            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            throw $e;
        }

        $this->audit->record(
            action: 'invoice.issue',
            actorId: $actorId,
            entityType: 'invoices',
            entityId: $invoiceId,
            metadata: [
                'invoice_number' => $invoiceNumber,
                'order_id' => Uuid::toString($orderId),
                'gross_cents' => (int) $order['gross_cents'],
            ]
        );

        return [
            'invoice_id' => Uuid::toString($invoiceId),
            'invoice_number' => $invoiceNumber,
            'created' => true,
        ];
    }

    /**
     * Verify a series: chain integrity plus the absence of gaps.
     *
     * @return array{ok:bool, checked:int, problems:list<string>}
     */
    public function verifySeries(string $seriesCode, string $docType = 'invoice'): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT sequence_no, invoice_number, issue_date, bill_vat_number,
                    bill_legal_name, net_cents, tax_cents, gross_cents, currency,
                    prev_hash, doc_hash
               FROM invoices
              WHERE series_code = ? AND doc_type = ?
              ORDER BY sequence_no ASC'
        );
        $stmt->execute([$seriesCode, $docType]);

        $problems = [];
        $expectedPrev = null;
        $expectedSeq = null;
        $checked = 0;

        while ($row = $stmt->fetch()) {
            $checked++;
            $seq = (int) $row['sequence_no'];

            if ($expectedSeq !== null && $seq !== $expectedSeq) {
                $problems[] = sprintf(
                    'Gap in series %s: expected %d, found %d. A missing number reads as a '
                    . 'suppressed sale and must be explained.',
                    $seriesCode,
                    $expectedSeq,
                    $seq
                );
            }

            if ($expectedPrev !== null && $row['prev_hash'] !== $expectedPrev) {
                $problems[] = sprintf(
                    'Chain break at %s: prev_hash does not match the preceding document.',
                    $row['invoice_number']
                );
            }

            $canonical = $this->canonicalDocumentString([
                'number' => (string) $row['invoice_number'],
                'issue_date' => (string) $row['issue_date'],
                'vat' => (string) ($row['bill_vat_number'] ?? ''),
                'legal_name' => (string) $row['bill_legal_name'],
                'net' => (int) $row['net_cents'],
                'tax' => (int) $row['tax_cents'],
                'gross' => (int) $row['gross_cents'],
                'currency' => (string) $row['currency'],
            ]);

            $recomputed = hash('sha256', ((string) ($row['prev_hash'] ?? '')) . $canonical, true);

            if (!hash_equals((string) $row['doc_hash'], $recomputed)) {
                $problems[] = sprintf(
                    'Document %s was altered after issue: contents do not match doc_hash.',
                    $row['invoice_number']
                );
            }

            $expectedPrev = (string) $row['doc_hash'];
            $expectedSeq = $seq + 1;
        }

        return ['ok' => $problems === [], 'checked' => $checked, 'problems' => $problems];
    }

    /**
     * Ensure a series row exists for a year. Call from a deploy or new-year task,
     * not lazily on the issuing path.
     */
    public function ensureSeries(
        int $year,
        string $docType = 'invoice',
        ?string $atcudPrefix = null
    ): void {
        $seriesCode = ($docType === 'invoice' ? 'FT' : 'NC') . $year;

        $stmt = $this->pdo->prepare(
            'INSERT INTO document_series (id, doc_type, series_code, year, next_number, atcud_prefix)
             VALUES (?, ?, ?, ?, 1, ?)
             ON DUPLICATE KEY UPDATE atcud_prefix = COALESCE(VALUES(atcud_prefix), atcud_prefix)'
        );
        $stmt->execute([Uuid::v7(), $docType, $seriesCode, $year, $atcudPrefix]);
    }

    /** @return array<string, mixed> */
    private function loadOrderForInvoicing(string $orderId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT o.id, o.org_id, o.currency, o.net_cents, o.tax_cents, o.gross_cents,
                    o.payment_status, o.status,
                    g.legal_name, g.vat_number, g.registered_address,
                    g.tax_exempt, g.payment_terms_days
               FROM orders o
               JOIN organisations g ON g.id = o.org_id
              WHERE o.id = ?
              FOR UPDATE'
        );
        $stmt->execute([$orderId]);
        $order = $stmt->fetch();

        if ($order === false) {
            throw new \RuntimeException('Order not found: ' . Uuid::toString($orderId));
        }

        if (in_array((string) $order['status'], ['draft', 'declined', 'cancelled'], true)) {
            throw new \DomainException(sprintf(
                'Refusing to invoice an order in status "%s".',
                $order['status']
            ));
        }

        if ((int) $order['gross_cents'] <= 0) {
            throw new \DomainException('Refusing to invoice a zero-value order.');
        }

        return $order;
    }

    /** @return array<string, mixed> */
    private function lockSeries(string $docType, int $year): array
    {
        $seriesCode = ($docType === 'invoice' ? 'FT' : 'NC') . $year;

        // FOR UPDATE is what makes numbering gapless under concurrency: the
        // second issuer waits here rather than reading the same next_number.
        $stmt = $this->pdo->prepare(
            'SELECT id, series_code, next_number, atcud_prefix
               FROM document_series
              WHERE doc_type = ? AND series_code = ? AND is_active = 1
              FOR UPDATE'
        );
        $stmt->execute([$docType, $seriesCode]);
        $series = $stmt->fetch();

        if ($series === false) {
            throw new \RuntimeException(sprintf(
                'No active document series "%s". Call ensureSeries(%d) during deployment.',
                $seriesCode,
                $year
            ));
        }

        return $series;
    }

    private function seriesHead(string $docType, string $seriesCode): ?string
    {
        $stmt = $this->pdo->prepare(
            'SELECT doc_hash FROM invoices
              WHERE doc_type = ? AND series_code = ?
              ORDER BY sequence_no DESC LIMIT 1'
        );
        $stmt->execute([$docType, $seriesCode]);
        $head = $stmt->fetchColumn();

        return $head === false || $head === null ? null : (string) $head;
    }

    /**
     * Canonical string committed to by doc_hash.
     *
     * Field order and separator are fixed forever: change them and every stored
     * hash stops verifying. Amounts are integer minor units, so no locale or
     * float formatting can creep in.
     *
     * @param array{number:string, issue_date:string, vat:string, legal_name:string,
     *              net:int, tax:int, gross:int, currency:string} $doc
     */
    private function canonicalDocumentString(array $doc): string
    {
        return implode('|', [
            'v1',
            $doc['number'],
            $doc['issue_date'],
            VatNumber::normalise($doc['vat']),
            mb_strtoupper(trim($doc['legal_name']), 'UTF-8'),
            (string) $doc['net'],
            (string) $doc['tax'],
            (string) $doc['gross'],
            strtoupper($doc['currency']),
        ]);
    }

    /**
     * ATCUD placeholder: '<AT series validation code>-<sequence>'.
     *
     * Returns null without an AT-issued prefix, rather than fabricating a
     * plausible-looking code. A wrong ATCUD on a real invoice is a filing
     * problem, not a cosmetic one.
     */
    private function atcud(?string $atcudPrefix, int $sequenceNo): ?string
    {
        return $atcudPrefix === null || $atcudPrefix === ''
            ? null
            : sprintf('%s-%d', $atcudPrefix, $sequenceNo);
    }
}
