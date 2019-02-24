<?php 
declare (strict_types = 1);
require_once('../libs/XTEA.class.php');
$keys_binary = random_bytes(4 * 4);
$keys_array = XTEA::binary_key_to_int_array($keys_binary);
$data = random_bytes(1 * 1024); // 1KB
$time = microtime(true);
for ($i = 0; $i < 1024; ++$i) {
    XTEA::encrypt($data, $keys_array);
}
$time = microtime(true) - $time;
echo "encrypted 1 kilobyte 1024 times in " . number_format($time, 9) . " seconds.\n";