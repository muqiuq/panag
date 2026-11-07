<?php
// Minimal MaxMind DB (MMDB v2) writer for test fixtures – IPv6 tree with IPv4 under ::/96, 24-bit records.
// Supports the data types the fixtures need: map, utf8 string, uint16/32/64, boolean, array.
// Spec: https://maxmind.github.io/MaxMind-DB/  (dev/tests only – never used in production)

final class MmdbWriter
{
    /** @var list<array{0: mixed, 1: mixed}> node => [left, right]; child: null | ['n', index] | ['d', record] */
    private array $nodes = [[null, null]];

    public function __construct(private string $databaseType, private string $description = 'PANAG test fixture')
    {
    }

    /** Insert a network; later, more specific networks override earlier ones. */
    public function insert(string $cidr, array $record): void
    {
        [$ip, $prefix] = array_pad(explode('/', $cidr, 2), 2, null);
        $bin = (string)inet_pton((string)$ip);
        $bits = '';
        foreach (str_split($bin) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        if (strlen($bin) === 4) {
            $bits = str_repeat('0', 96) . $bits; // IPv4 lives under ::/96 (what the reader looks up)
            $prefix = 96 + (int)($prefix ?? 32);
        } else {
            $prefix = (int)($prefix ?? 128);
        }
        $node = 0;
        for ($i = 0; $i < $prefix; $i++) {
            $bit = (int)$bits[$i];
            if ($i === $prefix - 1) {
                $this->nodes[$node][$bit] = ['d', $record];
                return;
            }
            $child = $this->nodes[$node][$bit];
            if (is_array($child) && $child[0] === 'n') {
                $node = $child[1];
                continue;
            }
            // empty or a larger network's data: split it into a new node
            $this->nodes[] = [$child, $child];
            $new = count($this->nodes) - 1;
            $this->nodes[$node][$bit] = ['n', $new];
            $node = $new;
        }
    }

    public function write(string $file): void
    {
        $count = count($this->nodes);
        $data = '';
        $offsets = [];
        $tree = '';
        foreach ($this->nodes as $pair) {
            foreach ($pair as $child) {
                if ($child === null) {
                    $value = $count;
                } elseif ($child[0] === 'n') {
                    $value = $child[1];
                } else {
                    $encoded = self::encode($child[1]);
                    if (!isset($offsets[$encoded])) {
                        $offsets[$encoded] = strlen($data);
                        $data .= $encoded;
                    }
                    $value = $count + 16 + $offsets[$encoded];
                }
                $tree .= substr(pack('N', $value), 1); // 24-bit record
            }
        }
        $meta = self::encode([
            'node_count' => ['uint32', $count],
            'record_size' => ['uint16', 24],
            'ip_version' => ['uint16', 6],
            'database_type' => $this->databaseType,
            'languages' => ['en'],
            'binary_format_major_version' => ['uint16', 2],
            'binary_format_minor_version' => ['uint16', 0],
            'build_epoch' => ['uint64', time()],
            'description' => ['en' => $this->description],
        ]);
        file_put_contents($file, $tree . str_repeat("\0", 16) . $data . "\xAB\xCD\xEFMaxMind.com" . $meta);
    }

    /** @param mixed $value strings, bools, lists, maps, or ['uint16'|'uint32'|'uint64', int] */
    private static function encode($value): string
    {
        if (is_array($value) && count($value) === 2 && in_array($value[0] ?? null, ['uint16', 'uint32', 'uint64'], true) && is_int($value[1])) {
            $bytes = ltrim(pack('J', $value[1]), "\0");
            return match ($value[0]) {
                'uint16' => self::control(5, strlen($bytes)) . $bytes,
                'uint32' => self::control(6, strlen($bytes)) . $bytes,
                default => self::control(9, strlen($bytes)) . $bytes,
            };
        }
        if (is_int($value)) {
            return self::encode(['uint32', $value]);
        }
        if (is_bool($value)) {
            return self::control(14, $value ? 1 : 0);
        }
        if (is_string($value)) {
            return self::control(2, strlen($value)) . $value;
        }
        if (is_array($value) && array_is_list($value)) {
            return self::control(11, count($value)) . implode('', array_map([self::class, 'encode'], $value));
        }
        $out = self::control(7, count($value));
        foreach ((array)$value as $k => $v) {
            $out .= self::encode((string)$k) . self::encode($v);
        }
        return $out;
    }

    private static function control(int $type, int $size): string
    {
        if ($size < 29) {
            $sizeBits = $size;
            $extra = '';
        } elseif ($size < 285) {
            $sizeBits = 29;
            $extra = chr($size - 29);
        } else {
            $sizeBits = 30;
            $extra = pack('n', $size - 285);
        }
        if ($type <= 7) {
            return chr(($type << 5) | $sizeBits) . $extra;
        }
        return chr($sizeBits) . chr($type - 7) . $extra; // extended type
    }
}
