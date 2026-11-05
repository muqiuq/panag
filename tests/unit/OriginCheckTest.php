<?php
use PHPUnit\Framework\TestCase;

final class OriginCheckTest extends TestCase
{
    public function testMatchesHostWithNonDefaultPort(): void
    {
        // Regression: the old check compared only the origin host with HTTP_HOST ("host:8080").
        $this->assertTrue(origin_matches_host('http://172.17.0.2:8080', '172.17.0.2:8080'));
        $this->assertTrue(origin_matches_host('http://panag.lan', 'panag.lan'));
        $this->assertTrue(origin_matches_host('https://PANAG.lan', 'panag.lan'));
    }

    public function testRejectsForeignOrigins(): void
    {
        $this->assertFalse(origin_matches_host('http://evil.example', 'panag.lan'));
        $this->assertFalse(origin_matches_host('http://panag.lan:9999', 'panag.lan:8080'));
        $this->assertFalse(origin_matches_host('http://panag.lan', 'panag.lan:8080'));
        $this->assertFalse(origin_matches_host('null', 'panag.lan'));
        $this->assertFalse(origin_matches_host('http://panag.lan', ''));
    }
}
