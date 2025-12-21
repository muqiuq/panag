<?php
require_once __DIR__ . '/functions.php';

header('Content-Type: application/json');

// Simple harness to exercise add_address_list_entry.
$username = $_GET['username'] ?? 'testuser';
$address = $_GET['address'] ?? '10.0.0.0/24';
$name = $_GET['name'] ?? 'TestNet';
$timeout = $_GET['timeout'] ?? DEFAULT_TIMEOUT;

$network = ['name' => $name, 'address' => $address];
$result = add_address_list_entry($username, $network, $timeout);

$reply = [
    'input' => [
        'username' => $username,
        'network' => $network,
        'timeout' => $timeout,
    ],
    'result' => $result,
];

echo json_encode($reply);
exit;
?>
