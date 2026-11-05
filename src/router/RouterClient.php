<?php
// Access to the RouterOS device. All router communication goes through this interface,
// so tests can swap the implementation (FakeRouterClient) or point the REST client at the mock.
//
// Every method returns a result array:
//   ['success' => bool, 'data' => mixed, 'error' => ?string, 'status' => ?int, 'fingerprint' => ?string]

interface RouterClient
{
    /** List firewall address-list entries, optionally only those of one list. */
    public function listAddressList(?string $list = null): array;

    /** Create an address-list entry. $timeout in RouterOS format, e.g. "01:00:00". */
    public function addAddressListEntry(string $list, string $address, string $comment, string $timeout): array;

    /** Update fields (e.g. timeout) of an existing entry. */
    public function updateAddressListEntry(string $id, array $fields): array;

    public function removeAddressListEntry(string $id): array;

    public function identity(): array;

    public function clock(): array;

    public function resource(): array;

    public function wireguardPeers(): array;
}

function router_result(bool $success, $data = null, ?string $error = null, ?int $status = null, ?string $fingerprint = null): array
{
    return ['success' => $success, 'data' => $data, 'error' => $error, 'status' => $status, 'fingerprint' => $fingerprint];
}

function router(): RouterClient
{
    if (!isset($GLOBALS['PANAG_ROUTER'])) {
        $GLOBALS['PANAG_ROUTER'] = new RestRouterClient(
            (string)MIKROTIK_BASE_URL,
            (string)MIKROTIK_USERNAME,
            (string)MIKROTIK_PASSWORD,
            (string)MIKROTIK_CERT_FINGERPRINT,
            (int)MIKROTIK_CONNECT_TIMEOUT,
            (int)MIKROTIK_TIMEOUT
        );
    }
    return $GLOBALS['PANAG_ROUTER'];
}

/** Replace the router client (tests). */
function set_router(?RouterClient $client): void
{
    if ($client === null) {
        unset($GLOBALS['PANAG_ROUTER']);
        return;
    }
    $GLOBALS['PANAG_ROUTER'] = $client;
}
