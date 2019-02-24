<?php
require_once('xtea.class.php');
// Nigg says anal: 24008a10a9122d424ade3434e883f25ce0a2ea9fcd9b7915c6d1311c5253feb8b50a1698b470
// first 2 bytes are uint16_t packet_length (2400) so remove that: 8a10a9122d424ade3434e883f25ce0a2ea9fcd9b7915c6d1311c5253feb8b50a1698b470
// then there are 4 bytes that are NOT xtea-encryted, adler checksum of the following encrypted bytes, remove that: 2d424ade3434e883f25ce0a2ea9fcd9b7915c6d1311c5253feb8b50a1698b470


$xtea_key_binary = str_repeat("\x00", 4 * 4);
$xtea_key_array = XTEA::binary_key_to_int_array($xtea_key_binary);
$bin = hex2bin('2d424ade3434e883f25ce0a2ea9fcd9b7915c6d1311c5253feb8b50a1698b470');
$i = 0;
echo "size: " . strlen($bin) . "\n";
while (($len = strlen($bin)) > 0) {
    try {
        $decrypted = XTEA::decrypt(pad($bin, 8), $xtea_key_array, 32);
    } catch (Throwable $ex) {
        ///
        $decrypted = '';
    }
    echo "{$i}: ";
    echo " uint8: " . from_uint8_t(substr($bin, 0, 2));
    if ($len >= 2) {
        echo " uint16: " . from_little_uint16_t(substr($bin, 0, 2));
        if ($len >= 4) {
            echo " uint32: " . from_little_uint32_t(substr($bin, 0, 4));
        }
    } 
    echo " decrypted: ";

    $ipos = stripos($decrypted, 'anal');
    if (false !== $ipos) {
        echo ("!!!!!!!!!!!!!!!!!!!!!!!!!! ");
        var_dump($decrypted);
    } else {
        var_dump($ipos);
    }
    //echo "\n";
    ++$i;
    $bin = substr($bin, 1);
}

function pad(string $data, int $multiple)
{
    $len = strlen($data);
    if ((($len % $multiple) !== 0)) {
        $nearest = (int)(ceil($len / $multiple) * $multiple);
        assert($nearest !== $len);
        assert($nearest > $len);
        $data .= str_repeat("\x00", $nearest - $len);
        $len = $nearest;
    }
    return $data;
}

function to_uint8_t(int $i) : string
{
    return pack('C', $i);
}
function from_uint8_t(string $i) : int
{
	// ord($i) , i know.
    $arr = unpack("Cuint8_t", $i);
    return $arr['uint8_t'];
}
function from_little_uint16_t(string $i) : int
{
    $arr = unpack('vuint16_t', $i);
    return $arr['uint16_t'];
}
function from_big_uint16_t(string $i) : int
{
    $arr = unpack('nuint16_t', $i);
    return $arr['nint16_t'];
}
function to_little_uint16_t(int $i) : string
{
    return pack('v', $i);
}
function to_big_uint16_t(int $i) : string
{
    return pack('n', $i);
}
function from_little_uint32_t(string $i) : int
{
    $arr = unpack('Vuint32_t', $i);
    return $arr['uint32_t'];
}
function from_big_uint32_t(string $i) : int
{
    $arr = unpack('Nuint32_t', $i);
    return $arr['uint32_t'];
}
function to_little_uint32_t(int $i) : string
{
    return pack('V', $i);
}
function to_big_uint32_t(int $i) : string
{
    return pack('N', $i);
}
function from_little_uint64_t(string $i) : int
{
    $arr = unpack('Puint64_t', $i);
    return $arr['uint64_t'];
}
function from_big_uint64_t(string $i) : int
{
    $arr = unpack('Juint64_t', $i);
    return $arr['uint64_t'];
}
function to_little_uint64_t(int $i) : string
{
    return pack('P', $i);
}
function to_big_uint64_t(int $i) : string
{
    return pack('J', $i);
}
/* splits up Nagle Algorithm combined data */
function hhb_denagle(string $nagled_binary) : array
{
    $ret = array();
    $pos = 0;
    $len = strlen($nagled_binary);
    while ($len > 0) {
        if ($len < 2) {
            throw new Exception('Invalid Nagle algorithm: at byte ' . $pos . ', length header is <2 bytes long!');
        }
        $sublen = from_little_uint16_t($nagled_binary[0] . $nagled_binary[1]);
        $nagled_binary = substr($nagled_binary, 2);
        $len -= 2;
        if ($len < $sublen) {
            throw new Exception('Invalid Nagle algorithm: length header at byte ' . $pos . ' specify a length of ' . $sublen . ' bytes, but only ' . $len . ' bytes remain!');
        }
        $ret[] = substr($nagled_binary, 0, $sublen);
        $nagled_binary = substr($nagled_binary, $sublen);
        $len -= $sublen;
        $pos += $sublen + 2;
    }
    return $ret;
}