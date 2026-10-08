<?php

declare(strict_types=1);

namespace ScannerTrap\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ScannerTrap\SubnetPolicy;

final class SubnetPolicyTest extends TestCase
{
    public function test_defaults_escalate_a_v4_slash_24_after_three_and_a_v6_slash_64_at_once(): void
    {
        $policy = new SubnetPolicy();

        $v4 = $policy->escalationFor('45.155.205.77');
        $v6 = $policy->escalationFor('2a01:4f8:c0c:1234::7');

        $this->assertNotNull($v4);
        $this->assertNotNull($v6);
        $this->assertSame(['45.155.205.0/24', '4/24', 3, 86400], [$v4->network, $v4->token, $v4->threshold, $v4->window]);
        $this->assertSame(['2a01:4f8:c0c:1234::/64', '6/64', 1, 86400], [$v6->network, $v6->token, $v6->threshold, $v6->window]);
    }

    public function test_reserved_networks_and_garbage_never_escalate(): void
    {
        $policy = new SubnetPolicy();

        $this->assertNull($policy->escalationFor('10.0.0.7'));
        $this->assertNull($policy->escalationFor('203.0.113.7'));
        $this->assertNull($policy->escalationFor('fd00::7'));
        $this->assertNull($policy->escalationFor('nonsense'));
    }

    public function test_config(): void
    {
        $this->assertNull(SubnetPolicy::fromConfig(false));
        $this->assertEquals(new SubnetPolicy(), SubnetPolicy::fromConfig(null));
        $custom = SubnetPolicy::fromConfig(['v4Prefix' => 20, 'v4Threshold' => 5, 'window' => 3600]);
        $this->assertNotNull($custom);
        $escalation = $custom->escalationFor('45.155.205.77');
        $this->assertSame(['45.155.192.0/20', 5, 3600], [$escalation?->network, $escalation?->threshold, $escalation?->window]);
    }

    /** @return array<string, array{mixed}> */
    public static function brokenConfigs(): array
    {
        return [
            'not an array' => ['yes'],
            'v4 prefix too narrow' => [['v4Prefix' => 32]],
            'v4 prefix too wide' => [['v4Prefix' => 7]],
            'v6 prefix too wide' => [['v6Prefix' => 15]],
            'zero threshold' => [['v4Threshold' => 0]],
            'short window' => [['window' => 10]],
            'string number' => [['v4Prefix' => '24']],
        ];
    }

    /** @param mixed $config */
    #[\PHPUnit\Framework\Attributes\DataProvider('brokenConfigs')]
    public function test_a_broken_config_is_refused(mixed $config): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SubnetPolicy::fromConfig($config);
    }
}
