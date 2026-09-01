<?php

declare(strict_types=1);

namespace Manager2\Auth;

/**
 * VIES VAT existence check (EU Commission SOAP/REST service).
 *
 * Operational realities to design around, because VIES is not a reliable
 * dependency and treating it as one produces an onboarding flow that
 * intermittently rejects legitimate customers:
 *
 *  - Individual member-state registries go offline for hours. A failure is
 *    'inconclusive', never 'invalid'.
 *  - There is no SLA and no authentication.
 *  - Rate limits are undocumented and enforced by IP.
 *  - Name matching is fuzzy; several states return no name at all, only a
 *    valid/invalid flag.
 *
 * So: never block onboarding on a VIES timeout. Record the outcome as
 * inconclusive, queue a retry, and let a human decide. And always persist the
 * consultation number for a 'valid' answer — it is the seller's evidence of
 * having checked, which is what a tax audit asks for.
 */
final class Vies
{
    private const ENDPOINT = 'https://ec.europa.eu/taxation_customs/vies/rest-api/ms/%s/vat/%s';

    public function __construct(
        private readonly int $timeoutSeconds = 8,
        private readonly ?string $requesterVat = null
    ) {
    }

    /**
     * @return array{
     *     outcome: 'pass'|'fail'|'inconclusive',
     *     valid: bool|null,
     *     name: string|null,
     *     address: string|null,
     *     consultation_ref: string|null,
     *     checked_at: string,
     *     error: string|null
     * }
     */
    public function check(string $vatNumber, ?string $fallbackCountry = null): array
    {
        [$country, $body] = VatNumber::split($vatNumber, $fallbackCountry);

        $result = [
            'outcome' => 'inconclusive',
            'valid' => null,
            'name' => null,
            'address' => null,
            'consultation_ref' => null,
            'checked_at' => gmdate('c'),
            'error' => null,
        ];

        if (!VatNumber::isPlausible($vatNumber, $fallbackCountry)) {
            return [...$result, 'outcome' => 'fail', 'valid' => false,
                'error' => 'Failed syntax or checksum validation; not sent to VIES.'];
        }

        $url = sprintf(self::ENDPOINT, rawurlencode($country), rawurlencode($body));

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
                'header' => "Accept: application/json\r\nUser-Agent: manager2/1.0\r\n",
            ],
        ]);

        $raw = @file_get_contents($url, false, $context);

        if ($raw === false) {
            return [...$result, 'error' => 'VIES unreachable.'];
        }

        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        if ($status !== 200) {
            return [...$result, 'error' => "VIES returned HTTP {$status}."];
        }

        try {
            /** @var array<string, mixed> $payload */
            $payload = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return [...$result, 'error' => 'Malformed VIES response: ' . $e->getMessage()];
        }

        // A member-state registry being down is reported inside a 200 body.
        $msError = $payload['userError'] ?? null;
        if (is_string($msError) && !in_array($msError, ['VALID', 'INVALID', ''], true)) {
            return [...$result, 'error' => "VIES member state reported: {$msError}"];
        }

        $isValid = (bool) ($payload['isValid'] ?? false);

        return [
            'outcome' => $isValid ? 'pass' : 'fail',
            'valid' => $isValid,
            'name' => self::cleanField($payload['name'] ?? null),
            'address' => self::cleanField($payload['address'] ?? null),
            'consultation_ref' => self::cleanField($payload['requestIdentifier'] ?? null),
            'checked_at' => gmdate('c'),
            'error' => null,
        ];
    }

    /** VIES pads unavailable fields with '---'. */
    private static function cleanField(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $trimmed = trim($value);

        return $trimmed === '' || trim($trimmed, '-') === '' ? null : $trimmed;
    }
}
