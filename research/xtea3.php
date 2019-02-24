<?php
declare (strict_types = 1);
require_once('hhb_.inc.php');
require_once('hhb_datatypes.inc.php');
require_once('xtea_helper.php');

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */


/*static*/ class Xtea
{
    const PAD_NONE = 0;
    const PAD_0x00 = 1;
    const PAD_RANDOM = 2;
    // .. and PKCS#7 has been proposed
    /**
     * convert a binary string to xtea key array
     *
     * @param string $key
     * @param integer $padding_scheme
     * @return int[4]
     */
    public static function binary_key_to_int_array(string $key, int $padding_scheme = self::PAD_0x00) : array
    {
        if ($padding_scheme !== self::PAD_0x00 && $padding_scheme !== self::PAD_NONE) {
            //... i refuse to support PAD_RANDOM here...
            throw new \InvalidArgumentException("only PAD_NONE and PAD_0x00 is supported!");
        }
        $len = strlen($key);
        if ($len > 16) {
            throw new \InvalidArgumentException("the max length for a XTEA binary key is 16 bytes.");
        } elseif ($padding_scheme === self::PAD_NONE && $len !== 16) {
            throw new \InvalidArgumentException("with PAD_NONE the key has to be _EXACTLY_ 16 bytes long.");
        } elseif ($len < 16) {
            $key .= str_repeat("\x00", 16 - $len);
        } else {
            // all good
        }
        $ret = [];
        foreach (str_split($key, 4) as $key) {
            $ret[] = self::from_little_uint32_t($key);
        }
        assert(count($ret) === 4);
        return $ret;
    }
    /**
     * xtea-encrypt data
     *
     * @param string $data
     * @param int[4] $keys
     * @param integer $padding_scheme
     * @param integer $rounds
     * @return string
     */
    public static function encrypt(string $data, array $keys, int $padding_scheme = self::PAD_NONE, int $rounds = 32) : string
    {
        if ($padding_scheme < 0 || $padding_scheme > 2) {
            throw new \InvalidArgumentException("only PAD_NONE and PAD_0x00 and PAD_RANDOM supported!");
        }
        if (count($keys) !== 4) {
            throw new \InvalidArgumentException('count($keys) !== 4');
        }
        for ($i = 0; $i < 4; ++$i) {
            if (!is_int($keys[$i])) {
                throw new \InvalidArgumentException('!is_int($keys[' . $i . '])');
            }
            if ($keys[$i] < 0) {
                throw new \InvalidArgumentException('$keys[' . $i . '] < 0');
            }
            if ($keys[$i] > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('$keys[' . $i . '] > 0xFFFFFFFF');
            }
        }
        if ($rounds < 0) {
            throw new \InvalidArgumentException(" < 0 rounds is impossible (and <32 is probably a bad idea)");
        }
        $len = strlen($data);
        if ($len === 0 || (($len % 8) !== 0)) {
            if ($padding_scheme === self::PAD_NONE) {
                throw new \InvalidArgumentException("with PAD_NONE the data MUST be a multiple of 8 bytes!");
            } else {
                // encrypt_unsafe will take care of it.
            }
        }
        // we have now verified that everything is safe.
        return self::encrypt_unsafe($data, $keys, $padding_scheme, $rounds);
    }
    /**
     * faster version of encrypt(), lacking input validation.
     *
     * @param string $data
     * @param int[4] $keys
     * @param integer $padding_scheme
     * @param integer $rounds
     * @return string
     */
    public static function encrypt_unsafe(string $data, array $keys, int $padding_scheme = self::PAD_NONE, int $rounds = 32) : string
    {
        $len = strlen($data);
        if ($len === 0) {
            $len = 8;
            if ($padding_scheme === self::PAD_0x00) {
                $data = str_repeat("\x00", 8);
            } else {
                // self::PAD_RANDOM
                $data = random_bytes(8);
            }
        } elseif ((($len % 8) !== 0)) {
            $nearest = (int)(ceil($len / 8) * 8);
            assert($nearest !== $len);
            assert($nearest > $len);
            if ($padding_scheme === self::PAD_0x00) {
                $data .= str_repeat("\x00", $nearest - $len);
            } else {
                // self::PAD_RANDOM
                $data .= random_bytes($nearest - $len);
            }
            $len = $nearest;
        }
        // good to go
        $ret = '';
        for ($i = 0; $i < $len; $i += 8) {
            $i1 = self::from_little_uint32_t(substr($data, $i, 4));
            $i2 = self::from_little_uint32_t(substr($data, $i + 4, 4));
            self::encipher_unsafe($i1, $i2, $keys, $rounds);
            $ret .= self::to_little_uint32_t($i1);
            $ret .= self::to_little_uint32_t($i2);
        }
        return $ret;
    }
    /**
     * xtea-decrypt data
     *
     * @param string $data
     * @param int[4] $keys
     * @param integer $rounds
     * @return string decrypted
     */
    public static function decrypt(string $data, array $keys, int $rounds = 32) : string
    {
        $len = strlen($data);
        if ($len < 8) {
            throw new \InvalidArgumentException("this cannot be (intact) xtea-encrypted data, it's less than 8 bytes long (the minimum xtea length)");
        }
        if (($len % 8) !== 0) {
            throw new \InvalidArgumentException("this cannot be (intact) xtea-encrypted data, the length is not a multiple of 8 bytes.");
        }
        if (count($keys) !== 4) {
            throw new \InvalidArgumentException('count($keys) !== 4');
        }
        for ($i = 0; $i < 4; ++$i) {
            if (!is_int($keys[$i])) {
                throw new \InvalidArgumentException('!is_int($keys[' . $i . '])');
            }
            if ($keys[$i] < 0) {
                throw new \InvalidArgumentException('$keys[' . $i . '] < 0');
            }
            if ($keys[$i] > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('$keys[' . $i . '] > 0xFFFFFFFF');
            }
        }
        if ($rounds < 0) {
            throw new \InvalidArgumentException(" < 0 rounds is impossible (and <32 is probably a bad idea)");
        }
        return self::decrypt_unsafe($data, $keys, $rounds);
    }
    /**
     * faster version of decrypt() but lacking input validation.
     *
     * @param string $data
     * @param int[4] $keys
     * @param integer $rounds
     * @return string decrypted
     */
    public static function decrypt_unsafe(string $data, array $keys, int $rounds = 32) : string
    {
        // good to go
        $ret = '';
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 8) {
            $i1 = self::from_little_uint32_t(substr($data, $i, 4));
            $i2 = self::from_little_uint32_t(substr($data, $i + 4, 4));
            self::decipher_unsafe($i1, $i2, $keys, $rounds);
            $ret .= self::to_little_uint32_t($i1);
            $ret .= self::to_little_uint32_t($i2);
        }
        return $ret;

    }

    //////////// internal functions ///////////////////
    protected static function from_little_uint32_t(string $i) : int
    {
        $arr = unpack('Vuint32_t', $i);
        return $arr['uint32_t'];
    }
    protected static function to_little_uint32_t(int $i) : string
    {
        return pack('V', $i);
    }
    protected static function encipher(int &$data1, int &$data2, array $keys, int $rounds)
    {
        {
        //<argument validation>
            if ($data1 < 0) {
                throw new \InvalidArgumentException('$data1 < 0');
            }
            if ($data2 < 0) {
                throw new \InvalidArgumentException('$data2 < 0');
            }
            if ($data1 > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('$data1 > 0xFFFFFFFF');
            }
            if ($data2 > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('$data2 > 0xFFFFFFFF');
            }

            if (count($keys) !== 4) {
                throw new \InvalidArgumentException('count($keys) !== 4');
            }
            for ($i = 0; $i < 4; ++$i) {
                if (!is_int($keys[$i])) {
                    throw new \InvalidArgumentException('!is_int($keys[' . $i . '])');
                }
                if ($keys[$i] < 0) {
                    throw new \InvalidArgumentException('$keys[' . $i . '] < 0');
                }
                if ($keys[$i] > 0xFFFFFFFF) {
                    throw new \InvalidArgumentException('$keys[' . $i . '] > 0xFFFFFFFF');
                }
            }
        // </argument_validation>
        }
        self::encipher_unsafe($data1, $data2, $keys, $rounds);
        return; // void
    }
    protected static function encipher_unsafe(int &$data1, int &$data2, array $keys, int $rounds) : void
    {
        $sum = 0;
        for ($i = 0; $i < $rounds; ++$i) {
            $data1 = self::_add(
                $data1,
                self::_add($data2 << 4 ^ self::_rshift($data2, 5), $data2) ^
                    self::_add($sum, $keys[$sum & 3])
            );
            $sum = self::_add($sum, 0x9e3779b9); // delta
            $data2 = self::_add(
                $data2,
                self::_add($data1 << 4 ^ self::_rshift($data1, 5), $data1) ^
                    self::_add($sum, $keys[self::_rshift($sum, 11) & 3])
            );
        }
        $data1 = (int)$data1;
        $data2 = (int)$data2;
    }
    protected static function decipher_unsafe(int &$data1, int &$data2, array $keys, int $rounds)
    {
        $sum = self::_add(0, 0x9E3779B9 * $rounds); // 0x9E3779B9 = delta
        for ($i = 0; $i < $rounds; ++$i) {
            $data2 = self::_add(
                $data2,
                -(self::_add($data1 << 4 ^ self::_rshift($data1, 5), $data1) ^
                    self::_add($sum, $keys[self::_rshift($sum, 11) & 3]))
            );
            $sum = self::_add($sum, -(0x9E3779B9)); // 0x9E3779B9 = delta
            $data1 = self::_add(
                $data1,
                -(self::_add($data2 << 4 ^ self::_rshift($data2, 5), $data2) ^
                    self::_add($sum, $keys[$sum & 3]))
            );
        }
        $data1 = (int)$data1;
        $data2 = (int)$data2;
    }
    /**
     *  Handle proper unsigned right shift, dealing with PHP's signed shift.
     * taken from https://github.com/pear/Crypt_Xtea/blob/trunk/Xtea.php
     *  @access private
     *  @since          2004/Sep/06
     *  @author         Jeroen Derks <jeroen@derks.it>
     */
    protected static function _rshift($integer, $n)
    {
        // convert to 32 bits
        if (0xffffffff < $integer || -0xffffffff > $integer) {
            $integer = fmod($integer, 0xffffffff + 1);
        }
        // convert to unsigned integer
        if (0x7fffffff < $integer) {
            $integer -= 0xffffffff + 1.0;
        } elseif (-0x80000000 > $integer) {
            $integer += 0xffffffff + 1.0;
        }
        // do right shift
        if (0 > $integer) {
            $integer &= 0x7fffffff;                     // remove sign bit before shift
            $integer >>= $n;                            // right shift
            $integer |= 1 << (31 - $n);                 // set shifted sign bit
        } else {
            $integer >>= $n;                            // use normal right shift
        }
        return $integer;
    }

    /**
     *  Handle proper unsigned add, dealing with PHP's signed add.
     * taken from https://github.com/pear/Crypt_Xtea/blob/trunk/Xtea.php
     *  @access private
     *  @since          2004/Sep/06
     *  @author         Jeroen Derks <jeroen@derks.it>
     */
    function _add($i1, $i2)
    {
        $result = 0.0;
        foreach ([$i1, $i2] as $value) {
            // remove sign if necessary
            if (0.0 > $value) {
                $value -= 1.0 + 0xffffffff;
            }
            $result += $value;
        }
        // convert to 32 bits
        if (0xffffffff < $result || -0xffffffff > $result) {
            $result = fmod($result, 0xffffffff + 1);
        }
        // convert to signed integer
        if (0x7fffffff < $result) {
            $result -= 0xffffffff + 1.0;
        } elseif (-0x80000000 > $result) {
            $result += 0xffffffff + 1.0;
        }
        return $result;
    }
}



$keys_binary = random_bytes(4 * 4);
$keys_array = [];

foreach (str_split($keys_binary, 4) as $tmp) {
    $keys_array[] = from_little_uint32_t($tmp);
}
unset($tmp);


$correct = new Xtea_helper($keys_binary);
$data = "hello world!1234";
$mul = 1030;
$data = random_bytes($mul * 8);
if(strlen($data)!==($mul*8)){
    die("WTF!!!");
}
$encrypted_cpp = $correct->encrypt($data);
$encrypted_php = Xtea::encrypt($data, $keys_array);
$decrypted_cpp = $correct->decrypt($encrypted_cpp);
$decrypted_php = Xtea::decrypt($encrypted_php, $keys_array);

hhb_var_dump(
    $encrypted_php === $encrypted_cpp,
    $decrypted_cpp === $decrypted_php,
    $decrypted_cpp === $data,
    $decrypted_php === $data
    //,$data
);
$data = bin2hex($data);

function encrypt(string $data, array $keys)
{
    if ((strlen($data) % 8) !== 0) {
        throw new \InvalidArgumentException();
    }
    if (count($keys) !== 4) {
        throw new \InvalidArgumentException();
    }
    $ret = '';
    foreach (str_split($data, 8) as $data) {
        $chunks = str_split($data, 4);
        $i1 = from_little_uint32_t($chunks[0]);
        $i2 = from_little_uint32_t($chunks[1]);
        encipher($i1, $i2, $keys);
        $ret .= to_little_uint32_t($i1);
        $ret .= to_little_uint32_t($i2);
    }
    return $ret;
}


function encipher(int &$data1, int &$data2, array $keys)
{
    {
        //<argument validation>
        if ($data1 < 0) {
            throw new \InvalidArgumentException('$data1 < 0');
        }
        if ($data2 < 0) {
            throw new \InvalidArgumentException('$data2 < 0');
        }
        if ($data1 > 0xFFFFFFFF) {
            throw new \InvalidArgumentException('$data1 > 0xFFFFFFFF');
        }
        if ($data2 > 0xFFFFFFFF) {
            throw new \InvalidArgumentException('$data2 > 0xFFFFFFFF');
        }

        if (count($keys) !== 4) {
            throw new \InvalidArgumentException('count($keys) !== 4');
        }
        for ($i = 0; $i < 4; ++$i) {
            if (!is_int($keys[$i])) {
                throw new \InvalidArgumentException('!is_int($keys[' . $i . '])');
            }
            if ($keys[$i] < 0) {
                throw new \InvalidArgumentException('$keys[' . $i . '] < 0');
            }
            if ($keys[$i] > 0xFFFFFFFF) {
                throw new \InvalidArgumentException('$keys[' . $i . '] > 0xFFFFFFFF');
            }
        }
        // </argument_validation>
    }
    encipher_unsafe3($data1, $data2, $keys);
}

function encipher_unsafe3(int &$data1, int &$data2, array $keys, $rounds = 32)
{
    $y = $data1;
    $z = $data2;
    $sum = 0;
    $delta = 0x9e3779b9;
    /* start cycle */
    for ($i = 0; $i < $rounds; ++$i) {
        $y = _add(
            $y,
            _add($z << 4 ^ _rshift($z, 5), $z) ^
                _add($sum, $keys[$sum & 3])
        );
        $sum = _add($sum, $delta);
        $z = _add(
            $z,
            _add($y << 4 ^ _rshift($y, 5), $y) ^
                _add($sum, $keys[_rshift($sum, 11) & 3])
        );
    }
    /* end cycle */
    $v[0] = $y;
    $v[1] = $z;
    //return array($y, $z);
    $data1 = (int)$y;
    $data2 = (int)$z;
}

function encipher_unsafe(int &$data1, int &$data2, array $key)
{
    $v0 = $data1;
    $v1 = $data2;
    $sum = 0;
    $delta = 0x9E3779B9;
    for ($i = 0; $i < 32; ++$i) {
        $v0 += ((($v1 << 4) ^ ($v1 >> 5)) + $v1) ^ ($sum + $key[$sum & 3]);
        $sum += $delta;
        $v1 += ((($v0 << 4) ^ ($v0 >> 5)) + $v0) ^ ($sum + $key[($sum >> 11) & 3]);
    }
    $data1 = $v0;
    $data2 = $v1;
}
function _decipherLong($y, $z, &$w, &$k)
{
    // sum = delta<<5, in general sum = delta * n
    $sum = 0xC6EF3720;
    $delta = 0x9E3779B9;
    $n = (integer)$this->n_iter;
    while ($n-- > 0) {
        $z = $this->_add(
            $z,
            -($this->_add($y << 4 ^ $this->_rshift($y, 5), $y) ^
                $this->_add($sum, $k[$this->_rshift($sum, 11) & 3]))
        );
        $sum = $this->_add($sum, -$delta);
        $y = $this->_add(
            $y,
            -($this->_add($z << 4 ^ $this->_rshift($z, 5), $z) ^
                $this->_add($sum, $k[$sum & 3]))
        );
    }
    $w[0] = $y;
    $w[1] = $z;
}









/**
 *  Handle proper unsigned right shift, dealing with PHP's signed shift.
 * taken from https://github.com/pear/Crypt_Xtea/blob/trunk/Xtea.php
 *  @access private
 *  @since          2004/Sep/06
 *  @author         Jeroen Derks <jeroen@derks.it>
 */
function _rshift($integer, $n)
{
        // convert to 32 bits
    if (0xffffffff < $integer || -0xffffffff > $integer) {
        $integer = fmod($integer, 0xffffffff + 1);
    }
        // convert to unsigned integer
    if (0x7fffffff < $integer) {
        $integer -= 0xffffffff + 1.0;
    } elseif (-0x80000000 > $integer) {
        $integer += 0xffffffff + 1.0;
    }
        // do right shift
    if (0 > $integer) {
        $integer &= 0x7fffffff;                     // remove sign bit before shift
        $integer >>= $n;                            // right shift
        $integer |= 1 << (31 - $n);                 // set shifted sign bit
    } else {
        $integer >>= $n;                            // use normal right shift
    }
    return $integer;
}

function _add($v1, $v2)
{
    return call_user_func_array('add', func_get_args());
}
/**
 *  Handle proper unsigned add, dealing with PHP's signed add.
 * taken from https://github.com/pear/Crypt_Xtea/blob/trunk/Xtea.php
 *  @access private
 *  @since          2004/Sep/06
 *  @author         Jeroen Derks <jeroen@derks.it>
 */
function add($i1, $i2)
{
    $result = 0.0;
    foreach ([$i1, $i2] as $value) {
            // remove sign if necessary
        if (0.0 > $value) {
            $value -= 1.0 + 0xffffffff;
        }
        $result += $value;
    }
        // convert to 32 bits
    if (0xffffffff < $result || -0xffffffff > $result) {
        $result = fmod($result, 0xffffffff + 1);
    }
        // convert to signed integer
    if (0x7fffffff < $result) {
        $result -= 0xffffffff + 1.0;
    } elseif (-0x80000000 > $result) {
        $result += 0xffffffff + 1.0;
    }
    return $result;
}

die();
__halt_compiler ();
/* take 64 bits of data in data_in_out[0] and data_in_out[1] and 128 bits of key[0] - key[3] */
void encipher(uint32_t & data1, uint32_t & data2, uint32_t const key [4]) {
    uint32_t v0 = data1, v1 = data2, sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    data1 = v0;
    data2 = v1;
}

void decipher(uint32_t & data1, uint32_t & data2, uint32_t const key [4]) {
    const int num_rounds = 32;
    const uint32_t delta = 0x9E3779B9;
    uint32_t v0 = data1, v1 = data1, sum = delta * num_rounds;
    for (int i = 0; i < 32; i ++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    data1 = v0;
    data2 = v1;
}

void decipher(uint32_t v[2], uint32_t const key [4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
    for (i = 0; i < 32; i ++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}
