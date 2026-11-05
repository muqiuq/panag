<?php
// In-memory RouterClient for unit tests.

final class FakeRouterClient implements RouterClient
{
    /** @var array<int, array<string, string>> */
    public array $entries = [];
    public bool $failing = false;
    private int $nextId = 1;

    public function listAddressList(?string $list = null): array
    {
        if ($this->failing) {
            return router_result(false, [], 'HTTP 500', 500);
        }
        $items = array_values(array_filter($this->entries, fn($e) => $list === null || $e['list'] === $list));
        return router_result(true, $items, null, 200);
    }

    public function addAddressListEntry(string $list, string $address, string $comment, string $timeout): array
    {
        if ($this->failing) {
            return router_result(false, null, 'HTTP 500', 500);
        }
        $entry = ['.id' => '*' . strtoupper(dechex($this->nextId++)), 'list' => $list, 'address' => $address, 'comment' => $comment, 'timeout' => $timeout];
        $this->entries[] = $entry;
        return router_result(true, $entry, null, 201);
    }

    public function updateAddressListEntry(string $id, array $fields): array
    {
        foreach ($this->entries as $i => $e) {
            if ($e['.id'] === $id) {
                $this->entries[$i] = array_merge($e, array_map('strval', $fields));
                return router_result(true, $this->entries[$i], null, 200);
            }
        }
        return router_result(false, null, 'HTTP 404', 404);
    }

    public function removeAddressListEntry(string $id): array
    {
        foreach ($this->entries as $i => $e) {
            if ($e['.id'] === $id) {
                array_splice($this->entries, $i, 1);
                return router_result(true, null, null, 204);
            }
        }
        return router_result(false, null, 'HTTP 404', 404);
    }

    public function identity(): array
    {
        return router_result(true, ['name' => 'fake-router'], null, 200);
    }

    public function clock(): array
    {
        return router_result(true, ['date' => '2026-01-01', 'time' => '12:00:00', 'time-zone-name' => 'UTC'], null, 200);
    }

    public function resource(): array
    {
        return router_result(true, ['uptime' => '1d'], null, 200);
    }

    public function wireguardPeers(): array
    {
        return router_result(true, [], null, 200);
    }
}
