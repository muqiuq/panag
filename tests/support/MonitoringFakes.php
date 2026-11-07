<?php
// Fakes for the security monitoring tests: mail, GeoIP.

final class FakeMailer implements Mailer
{
    /** @var list<array{to: string, subject: string, body: string}> */
    public array $sent = [];
    /** @var array<string, string> recipient => error to simulate */
    public array $failFor = [];

    public function send(string $to, string $subject, string $body): ?string
    {
        if (isset($this->failFor[$to])) {
            return $this->failFor[$to];
        }
        $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        return null;
    }

    /** @return list<string> */
    public function recipients(): array
    {
        return array_column($this->sent, 'to');
    }
}

final class FakeGeoLookup implements GeoLookup
{
    /** @param array<string, array{country: ?string, asn: ?int, asn_org: ?string}> $map CIDR => result */
    public function __construct(private array $map)
    {
    }

    public function lookup(string $ip): ?array
    {
        if (!geoip_is_public_ip($ip)) {
            return null;
        }
        foreach ($this->map as $cidr => $result) {
            if (ip_in_cidr($ip, $cidr)) {
                return $result + ['available' => true];
            }
        }
        return ['country' => null, 'asn' => null, 'asn_org' => null, 'available' => true];
    }
}
