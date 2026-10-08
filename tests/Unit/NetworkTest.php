<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ScannerTrap\Network;

final class NetworkTest extends TestCase
{
    /** @return array<string, array{string, ?string}> */
    public static function parsed(): array
    {
        return [
            'v4 address' => ['45.155.205.7', '45.155.205.7/32'],
            'v4 network, host bits cleared' => ['45.155.205.7/24', '45.155.205.0/24'],
            'v4 /0' => ['8.8.8.8/0', '0.0.0.0/0'],
            'v6 address, collapsed' => ['2A01:4F8:C0C:1234:0:0:0:7', '2a01:4f8:c0c:1234::7/128'],
            'v6 /64' => ['2a01:4f8:c0c:1234:abcd::1/64', '2a01:4f8:c0c:1234::/64'],
            'v6 odd prefix' => ['2a01:4f8:c0c:12ff::/57', '2a01:4f8:c0c:1280::/57'],
            'mapped v6 address' => ['::ffff:45.155.205.7', '45.155.205.7/32'],
            'mapped v6 network' => ['::ffff:45.155.205.0/120', '45.155.205.0/24'],
            'mapped v6 too wide' => ['::ffff:0.0.0.0/95', null],
            'surrounding spaces' => [' 45.155.205.0/24 ', '45.155.205.0/24'],
            'prefix too long' => ['45.155.205.0/33', null],
            'v6 prefix too long' => ['2a01:4f8::/129', null],
            'empty prefix' => ['45.155.205.0/', null],
            'garbage' => ['office', null],
            'garbage prefix' => ['45.155.205.0/2x', null],
            'empty' => ['', null],
        ];
    }

    #[DataProvider('parsed')]
    public function test_parses_and_normalizes(string $value, ?string $cidr): void
    {
        $this->assertSame($cidr, Network::parse($value)?->cidr());
    }

    public function test_family_prefix_and_token(): void
    {
        $v4 = Network::parse('45.155.205.0/24');
        $v6 = Network::parse('2a01:4f8:c0c:1234::/64');

        $this->assertNotNull($v4);
        $this->assertNotNull($v6);
        $this->assertSame([4, 24, '4/24', '45.155.205.0'], [$v4->family, $v4->prefix, $v4->token(), $v4->address]);
        $this->assertSame([6, 64, '6/64'], [$v6->family, $v6->prefix, $v6->token()]);
    }

    public function test_of_gives_the_network_of_an_ip(): void
    {
        $this->assertSame('45.155.205.0/24', Network::of('45.155.205.77', 24)?->cidr());
        $this->assertSame('2a01:4f8:c0c:1234::/64', Network::of('2a01:4f8:c0c:1234:1:2:3:4', 64)?->cidr());
        $this->assertNull(Network::of('45.155.205.77', 33));
        $this->assertNull(Network::of('nonsense', 24));
    }

    public function test_candidates_cover_every_prefix_length(): void
    {
        $v4 = Network::candidates('45.155.205.77');
        $v6 = Network::candidates('2a01:4f8:c0c:1234::7');

        $this->assertCount(33, $v4);
        $this->assertSame('0.0.0.0/0', $v4['4/0']);
        $this->assertSame('45.155.205.0/24', $v4['4/24']);
        $this->assertSame('45.155.205.77/32', $v4['4/32']);
        $this->assertCount(129, $v6);
        $this->assertSame('2a01:4f8:c0c:1234::/64', $v6['6/64']);
        $this->assertSame([], Network::candidates('nonsense'));
    }

    /** @return array<string, array{string, string, bool}> */
    public static function containment(): array
    {
        return [
            'inside v4' => ['45.155.205.0/24', '45.155.205.200', true],
            'outside v4' => ['45.155.205.0/24', '45.155.206.1', false],
            'v6 inside' => ['2a01:4f8:c0c:1234::/64', '2a01:4f8:c0c:1234:ffff::1', true],
            'v6 outside' => ['2a01:4f8:c0c:1234::/64', '2a01:4f8:c0c:1235::1', false],
            'other family' => ['45.155.205.0/24', '2a01:4f8::1', false],
            'mapped address' => ['45.155.205.0/24', '::ffff:45.155.205.9', true],
            'garbage' => ['45.155.205.0/24', 'x', false],
        ];
    }

    #[DataProvider('containment')]
    public function test_contains(string $network, string $ip, bool $expected): void
    {
        $this->assertSame($expected, Network::parse($network)?->contains($ip));
    }

    public function test_overlaps(): void
    {
        $net = Network::parse('45.155.0.0/16');
        $this->assertNotNull($net);

        $this->assertTrue($net->overlaps(Network::parse('45.155.205.0/24') ?? $net));
        $this->assertTrue($net->overlaps(Network::parse('45.0.0.0/8') ?? $net));
        $this->assertFalse($net->overlaps(Network::parse('45.156.0.0/16') ?? $net));
        $this->assertFalse($net->overlaps(Network::parse('2a01::/16') ?? $net));
    }

    /** @return array<string, array{string, bool}> */
    public static function reserved(): array
    {
        return [
            'private 10/8 inside' => ['10.1.2.0/24', true],
            'private 172.16/12' => ['172.20.0.0/16', true],
            'private 192.168/16' => ['192.168.1.1', true],
            'loopback' => ['127.0.0.1', true],
            'cgnat' => ['100.64.1.0/24', true],
            'documentation' => ['203.0.113.0/24', true],
            'multicast and above' => ['224.0.0.0/3', true],
            'a wide net covering private space' => ['8.0.0.0/5', true],
            'public' => ['45.155.205.0/24', false],
            'v6 loopback' => ['::1', true],
            'v6 ula' => ['fd00:1::/32', true],
            'v6 link local' => ['fe80::1', true],
            'v6 documentation' => ['2001:db8:1::/48', true],
            'v6 public' => ['2a01:4f8:c0c:1234::/64', false],
        ];
    }

    #[DataProvider('reserved')]
    public function test_reserved_networks(string $network, bool $expected): void
    {
        $this->assertSame($expected, Network::parse($network)?->isReserved());
    }
}
