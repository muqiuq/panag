<?php
use PHPUnit\Framework\TestCase;

/** The admin alert list is paginated, sorted and searched on the server (admin/alerts.php). */
final class AlertListTest extends TestCase
{
    protected function setUp(): void
    {
        db()->exec('DELETE FROM alerts');
        $stmt = db()->prepare("INSERT INTO alerts (created_at, updated_at, user_label, rules, severity, summary, findings, status)
            VALUES (:t, :t, :u, :r, :s, :sum, '[]', :st)");
        $severities = ['info', 'low', 'medium', 'high', 'critical'];
        for ($i = 1; $i <= 120; $i++) {
            $stmt->execute([
                ':t' => 1_800_000_000 + $i * 60,
                ':u' => $i % 10 === 0 ? null : 'User ' . ($i % 7),
                ':r' => $i % 3 === 0 ? 'W2,W3' : 'P1',
                ':s' => $severities[$i % 5],
                ':sum' => 'Finding number ' . $i . ($i === 77 ? ' 100%_match' : ''),
                ':st' => $i % 4 === 0 ? 'resolved' : 'open',
            ]);
        }
    }

    public function testPagesAndTotals(): void
    {
        $order = alerts_order(null, null);
        $this->assertSame(['key' => 'time', 'dir' => 'desc'], ['key' => $order['key'], 'dir' => $order['dir']]);

        $first = alert_list('all', '', $order, 1);
        $this->assertSame(120, $first['total']);
        $this->assertSame(3, $first['pages']);
        $this->assertCount(ALERTS_PER_PAGE, $first['rows']);
        $this->assertSame('Finding number 120', $first['rows'][0]['summary'], 'newest first');

        $last = alert_list('all', '', $order, 3);
        $this->assertCount(20, $last['rows']);
        $this->assertSame('Finding number 1', end($last['rows'])['summary']);

        $this->assertSame(3, alert_list('all', '', $order, 99)['page'], 'page is clamped');
        $this->assertSame(1, alert_list('all', '', $order, -5)['page']);
    }

    public function testStatusFilter(): void
    {
        $order = alerts_order(null, null);
        $this->assertSame(90, alert_list('active', '', $order, 1)['total'], 'open + acknowledged');
        $this->assertSame(30, alert_list('resolved', '', $order, 1)['total']);
        $this->assertSame(90, alert_list("open' OR 1=1 --", '', $order, 1)['total'], 'unknown status falls back to active');
    }

    public function testSearchMatchesUserRulesAndSummaryLiterally(): void
    {
        $order = alerts_order(null, null);
        $this->assertSame(40, alert_list('all', 'W3', $order, 1)['total']);
        $this->assertSame(12, alert_list('all', 'system', $order, 1)['total'], 'alerts without user are "system"');
        $this->assertSame(1, alert_list('all', '100%_', $order, 1)['total'], '% and _ are literal');
    }

    public function testSortingIsWhitelisted(): void
    {
        $bySeverity = alert_list('all', '', alerts_order('severity', null), 1);
        $this->assertSame('critical', $bySeverity['rows'][0]['severity'], 'severity sorts by rank, highest first');
        $asc = alert_list('all', '', alerts_order('severity', 'asc'), 1);
        $this->assertSame('info', $asc['rows'][0]['severity']);

        $evil = alerts_order('created_at; DROP TABLE alerts', 'sideways');
        $this->assertSame('time', $evil['key']);
        $this->assertSame('desc', $evil['dir']);
        $this->assertSame(120, alert_list('all', '', $evil, 1)['total']);
    }
}
