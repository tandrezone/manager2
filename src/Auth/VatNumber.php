<?php

declare(strict_types=1);

namespace Manager2\Auth;

/**
 * VAT identification number normalisation and offline validation.
 *
 * Two distinct checks, and conflating them is a common and expensive mistake:
 *
 *  1. Syntax + checksum (this class). Free, instant, offline. Catches typos and
 *     invented numbers. Proves nothing about who owns the number.
 *  2. VIES existence check (Vies::class). Confirms the number is registered and
 *     returns the registered name. Only this establishes the counterparty is a
 *     real taxable person, and only this justifies zero-rating an intra-EU
 *     supply under Art. 138 of the VAT Directive.
 *
 * An account must not reach 'active' on syntax alone. Getting this wrong means
 * charging no VAT on a supply to a number that does not exist, and the seller
 * — not the buyer — owes the tax.
 */
final class VatNumber
{
    /**
     * Per-country syntax after the two-letter prefix is stripped.
     *
     * @var array<string, string>
     */
    private const PATTERNS = [
        'AT' => '/^U\d{8}$/',            'BE' => '/^0\d{9}$/',
        'BG' => '/^\d{9,10}$/',          'CY' => '/^\d{8}[A-Z]$/',
        'CZ' => '/^\d{8,10}$/',          'DE' => '/^\d{9}$/',
        'DK' => '/^\d{8}$/',             'EE' => '/^\d{9}$/',
        'EL' => '/^\d{9}$/',             'ES' => '/^[A-Z0-9]\d{7}[A-Z0-9]$/',
        'FI' => '/^\d{8}$/',             'FR' => '/^[A-Z0-9]{2}\d{9}$/',
        'HR' => '/^\d{11}$/',            'HU' => '/^\d{8}$/',
        'IE' => '/^(\d{7}[A-W]{1,2}|\d[A-Z+*]\d{5}[A-W])$/',
        'IT' => '/^\d{11}$/',            'LT' => '/^(\d{9}|\d{12})$/',
        'LU' => '/^\d{8}$/',             'LV' => '/^\d{11}$/',
        'MT' => '/^\d{8}$/',             'NL' => '/^\d{9}B\d{2}$/',
        'PL' => '/^\d{10}$/',            'PT' => '/^\d{9}$/',
        'RO' => '/^\d{2,10}$/',          'SE' => '/^\d{12}$/',
        'SI' => '/^\d{8}$/',             'SK' => '/^\d{10}$/',
        // Non-EU, kept because they appear in trade and need a sane answer.
        'GB' => '/^(\d{9}|\d{12}|(GD|HA)\d{3})$/',
        'CH' => '/^\d{9}(MWST|TVA|IVA)?$/',
        'NO' => '/^\d{9}MVA$/',
    ];

    /** Uppercase, strip everything that is not alphanumeric. */
    public static function normalise(string $vat): string
    {
        return strtoupper((string) preg_replace('/[^A-Za-z0-9]/', '', trim($vat)));
    }

    /**
     * Split a normalised number into country prefix and body.
     *
     * @return array{0:string, 1:string}
     */
    public static function split(string $vat, ?string $fallbackCountry = null): array
    {
        $normalised = self::normalise($vat);
        $prefix = substr($normalised, 0, 2);

        if (isset(self::PATTERNS[$prefix])) {
            return [$prefix, substr($normalised, 2)];
        }

        // Greece files as EL for VAT but is GR in ISO 3166.
        if ($prefix === 'GR') {
            return ['EL', substr($normalised, 2)];
        }

        $country = strtoupper($fallbackCountry ?? '');

        return [$country === 'GR' ? 'EL' : $country, $normalised];
    }

    /** Canonical storage form, e.g. 'PT501234567'. */
    public static function format(string $vat, ?string $fallbackCountry = null): string
    {
        [$country, $body] = self::split($vat, $fallbackCountry);

        return $country . $body;
    }

    /** Syntax check, plus a checksum where one is implemented. */
    public static function isPlausible(string $vat, ?string $fallbackCountry = null): bool
    {
        [$country, $body] = self::split($vat, $fallbackCountry);

        if (!isset(self::PATTERNS[$country]) || !preg_match(self::PATTERNS[$country], $body)) {
            return false;
        }

        return match ($country) {
            'PT' => self::portugueseChecksumOk($body),
            default => true,
        };
    }

    /**
     * Portuguese NIF/NIPC mod-11 checksum.
     *
     * Weights 9..2 across the first eight digits; the ninth is the check digit.
     * A remainder of 0 or 1 makes the check digit 0.
     */
    public static function portugueseChecksumOk(string $digits): bool
    {
        if (strlen($digits) !== 9 || !ctype_digit($digits)) {
            return false;
        }

        // Valid leading digits for natural persons, companies and other entities.
        $validFirst = ['1', '2', '3', '5', '6', '8'];
        $validFirstTwo = [
            '45', '70', '71', '72', '74', '75', '77', '78', '79',
            '90', '91', '98', '99',
        ];

        if (
            !in_array($digits[0], $validFirst, true)
            && !in_array(substr($digits, 0, 2), $validFirstTwo, true)
        ) {
            return false;
        }

        $sum = 0;
        for ($i = 0; $i < 8; $i++) {
            $sum += (int) $digits[$i] * (9 - $i);
        }

        $remainder = $sum % 11;
        $check = $remainder < 2 ? 0 : 11 - $remainder;

        return (int) $digits[8] === $check;
    }

    /** True where an intra-EU B2B supply may be zero-rated (reverse charge). */
    public static function isEuMemberState(string $country): bool
    {
        return isset(self::PATTERNS[strtoupper($country)])
            && !in_array(strtoupper($country), ['GB', 'CH', 'NO'], true);
    }
}
