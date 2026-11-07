<?php
// Build the GeoIP test databases for dev and E2E (./run.sh up / e2e call this):
//   php dev/geoip/build-fixtures.php [target-dir]   → country.mmdb, asn.mmdb (default: dev/geoip/)
// Uses documentation ranges only (RFC 5737, RFC 2544, RFC 3849) – no real addresses.
require_once __DIR__ . '/MmdbWriter.php';

/** [cidr, country, asn, organisation] – the place each test range pretends to be. */
const GEOIP_FIXTURES = [
    ['198.51.100.0/24', 'CH', 3303, 'Swisscom (Schweiz) AG'],
    ['192.0.2.0/24', 'DE', 3320, 'Deutsche Telekom AG'],
    ['203.0.113.0/24', 'US', 14061, 'DigitalOcean, LLC'],       // hosting network (rule W4)
    ['198.18.0.0/24', 'FR', 12322, 'Free SAS'],
    ['198.18.1.0/24', 'US', 7922, 'Comcast Cable Communications, LLC'],
    ['2001:db8::/32', 'CH', 3303, 'Swisscom (Schweiz) AG'],
];

$dir = rtrim($argv[1] ?? __DIR__, '/');
$country = new MmdbWriter('DBIP-Country-Lite');
$asn = new MmdbWriter('DBIP-ASN-Lite (compat=GeoLite2-ASN)');
foreach (GEOIP_FIXTURES as [$cidr, $code, $number, $org]) {
    $country->insert($cidr, ['country' => ['iso_code' => $code, 'names' => ['en' => $code]], 'continent' => ['code' => $code === 'US' ? 'NA' : 'EU']]);
    $asn->insert($cidr, ['autonomous_system_number' => $number, 'autonomous_system_organization' => $org]);
}
$country->write($dir . '/country.mmdb');
$asn->write($dir . '/asn.mmdb');
echo 'GeoIP fixtures written to ' . $dir . PHP_EOL;
