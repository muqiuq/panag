<?php
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    // RFC 6238 SHA1 test secret "12345678901234567890" in Base32
    private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testRfc6238Vectors(): void
    {
        // RFC values are 8 digits; PANAG uses the last 6.
        $this->assertSame('287082', totp(self::RFC_SECRET, 59));
        $this->assertSame('081804', totp(self::RFC_SECRET, 1111111109));
        $this->assertSame('050471', totp(self::RFC_SECRET, 1111111111));
        $this->assertSame('005924', totp(self::RFC_SECRET, 1234567890));
        $this->assertSame('279037', totp(self::RFC_SECRET, 2000000000));
    }

    public function testVerifyAcceptsAdjacentWindowOnly(): void
    {
        $secret = generate_otp_secret();
        $now = time();
        [$ok] = verify_otp_with_counter($secret, totp($secret, $now - OTP_STEP));
        $this->assertTrue($ok);
        [$ok] = verify_otp_with_counter($secret, totp($secret, $now - 5 * OTP_STEP));
        $this->assertFalse($ok);
        [$ok] = verify_otp_with_counter($secret, 'abcdef');
        $this->assertFalse($ok);
    }

    public function testGeneratedSecretIsBase32(): void
    {
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', generate_otp_secret());
    }
}
