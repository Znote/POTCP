<?php
require_once('../libs/hhb_.inc.php');
require_once('../libs/XTEA.class.php');
$xtea = new XTEA("secret Key");
$xtea->cbc = false;
$original = "\xFF";
for ($i = 0; $i < 10; ++$i) {
    $encrypted = $xtea->Encrypt($original);
    $decrypted = $xtea->Decrypt($encrypted);
    hhb_var_dump(
        $original,
        $encrypted,
        $decrypted,
        bin2hex($original),
        bin2hex($decrypted),
        ($original === $decrypted),
        $xtea->check_implementation()
    );
    if (($original === $decrypted)) {
        die("SUCCESS!");
    }
    $original .= "\xFF";
}