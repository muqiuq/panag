<?php
// Starts a helper process (mock RouterOS, TLS server) for integration tests.

final class BackgroundServer
{
    /** @var resource */
    private $process;
    public int $port;

    /** @param list<string> $command use {port} as placeholder */
    public function __construct(array $command, array $env = [])
    {
        $this->port = self::freePort();
        $cmd = array_map(fn($part) => str_replace('{port}', (string)$this->port, $part), $command);
        $process = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, null, array_merge(getenv(), $env));
        if (!is_resource($process)) {
            throw new RuntimeException('Could not start ' . implode(' ', $cmd));
        }
        $this->process = $process;
        $this->waitUntilListening();
    }

    public function stop(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
    }

    private static function freePort(): int
    {
        $sock = stream_socket_server('tcp://127.0.0.1:0');
        $name = stream_socket_get_name($sock, false);
        fclose($sock);
        return (int)substr(strrchr($name, ':'), 1);
    }

    private function waitUntilListening(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $conn = @stream_socket_client('tcp://127.0.0.1:' . $this->port, $errno, $errstr, 0.1);
            if ($conn) {
                fclose($conn);
                return;
            }
            usleep(50000);
        }
        throw new RuntimeException('Server on port ' . $this->port . ' did not start');
    }
}
