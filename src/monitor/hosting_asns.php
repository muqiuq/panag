<?php
// Networks of hosting, cloud and commercial VPN providers (rule W4). Connecting from such a network is
// unusual for a person and typical for proxies or rented servers. Extend via the W4 setting on admin/rules.php (default MONITOR_HOSTING_ASNS).
const HOSTING_ASNS = [
    16509, 14618, 8987,          // Amazon AWS
    15169, 396982, 19527,        // Google Cloud
    8075, 8068,                  // Microsoft Azure
    14061,                       // DigitalOcean
    16276,                       // OVH
    24940, 213230,               // Hetzner
    63949,                       // Akamai / Linode
    20473,                       // Vultr (Choopa)
    51167,                       // Contabo
    31898,                       // Oracle Cloud
    45102, 37963,                // Alibaba Cloud
    132203,                      // Tencent Cloud
    12876,                       // Scaleway
    60781, 28753,                // Leaseweb
    9009,                        // M247 (many VPN services)
    60068,                       // Datacamp / CDN77 (many VPN services)
    212238,                      // Datacamp
    136787, 147049,              // VPN providers (TEFINCOM, PacketHub)
    62240,                       // Clouvider
    53667,                       // FranTech / BuyVM
    36352,                       // ColoCrossing
    46606,                       // Unified Layer
    40021,                       // Contabo US
    199524,                      // G-Core Labs
    13335,                       // Cloudflare (WARP)
];

function is_hosting_asn(?int $asn): bool
{
    if ($asn === null) {
        return false;
    }
    return in_array($asn, HOSTING_ASNS, true) || in_array((string)$asn, array_map('strval', (array)rule_param('hosting_asns')), true);
}
