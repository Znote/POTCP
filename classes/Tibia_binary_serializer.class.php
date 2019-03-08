<?php
declare (strict_types = 1);
require_once('../libs/hhb_datatypes.inc.php'); // https://github.com/divinity76/hhb_.inc.php/blob/master/hhb_datatypes.inc.php
class Tibia_binary_serializer
{
    // should probably be protected not public, buuuut....
    public $buf = "";
    public function str(): string
    {
        return $this->buf;
    }
    function __construct(string $initial_buffer = "")
    {
        $this->buf = $initial_buffer;
    }
    public function eraseX(int $bytes_from_start, int $bytes_from_end = 0): void
    {
        if ($bytes_from_start < 0) {
            throw new \InvalidArgumentException('$bytes_from_start<0');
        }
        if ($bytes_from_end < 0) {
            throw new \InvalidArgumentException('$bytes_from_end<0');
        }
        $blen = strlen($this->buf);
        $total = $bytes_from_start + $bytes_from_end;
        if ($total > $blen) {
            // is UnderflowException appropriate here?
            throw new \UnderflowException("requested to remove {$total} byte(s) but only {$blen} byte(s) available!");
        }
        // unfortunately `negative zero` does not exist in this language, hence the checks are required..
        if ($bytes_from_start > 0 && $bytes_from_end > 0) {
            $this->buf = substr($this->buf, $bytes_from_start, -$bytes_from_end);
        } elseif ($bytes_from_start > 0) {
            $this->buf = substr($this->buf, $bytes_from_start);
        } elseif ($bytes_from_end > 0) {
            $this->buf = substr($this->buf, 0, -$bytes_from_end);
        } else {
            // nothing to do, both are 0.
        }
    }
    //<add_functions>
    public function add(string $bytes): void
    {
        $this->buf .= $bytes;
    }
    public function add_string(string $str): void
    {
        if (($len = strlen($str)) > 0xFFFF) {
            throw new \InvalidArgumentException("max length of a tibia string is 65535 bytes.");
        }
        $this->buf .= to_little_uint16_t($len) . $str;
    }
    public function add_position(int $x, int $y, int $z): void
    {
        //TODO: input validation/invalidArgumentException (x < 0 > 0xFFFF y < 0 > 0xFFFF z < 0 > 0xFF )
        $this->buf .= to_little_uint16_t($x) . to_little_uint16_t($y) . to_uint8_t($z);
    }
    public function addU8(int $i): void
    {
        if ($i < 0 || $i > 0xFF) {
            throw new \InvalidArgumentException("must be between 0-255");
        }
        $this->buf .= to_uint8_t($i);
    }
    public function addU16(int $i): void
    {
        if ($i < 0 || $i > 0xFFFF) {
            throw new \InvalidArgumentException("must be between 0-65535");
        }
        $this->buf .= to_little_uint16_t($i);
    }
    public function addU32(int $i): void
    {
        if ($i < 0 || $i > 0xFFFFFFFF) {
            throw new \InvalidArgumentException("must be between 0-4294967295");
        }
        $this->buf .= to_little_uint32_t($i);
    }
    // the tibia protocol never use 64 bit (nor above) integers AFAIK, so no need to support it here.
    //</add_functions>
    //<get_function>
    public function getU8(bool $exception_on_missing_bytes = true): ? int
    {
        $ret = $this->peekU8($exception_on_missing_bytes);
        if ($ret !== null) {
            $this->eraseX(1);
        }
        return $ret;
    }
    public function getU16(bool $exception_on_missing_bytes = true): ? int
    {
        $ret = $this->peekU16($exception_on_missing_bytes);
        if ($ret !== null) {
            $this->eraseX(2);
        }
        return $ret;
    }
    public function getU32(bool $exception_on_missing_bytes = true): ? int
    {
        $ret = $this->peekU32($exception_on_missing_bytes);
        if ($ret !== null) {
            $this->eraseX(4);
        }
        return $ret;
    }
    public function get_string(bool $exception_on_missing_header = true, bool $exception_on_invalid_header = true): ? string
    {
        $ret = $this->peek_string($exception_on_missing_header, $exception_on_invalid_header);
        if ($ret !== null) {
            $this->eraseX(strlen($ret) + 2); // 2: string size header
        }
        return $ret;
    }
    public function get_position(bool $exception_on_missing_bytes = true): ? array
    {
        $ret = $this->peek_position($exception_on_missing_bytes);
        if ($ret !== null) {
            $this->eraseX(5); // U16 x U16 y U8 z
        }
        return $ret;
    }
    //</get_functions>
    //<peek_functions>
    // TODO: until i can decide if it should return NULL or just return `as much as possible up to $number_of_bytes`, 
    // i'll keep this function disabled for now..
    // public function peek(int $number_of_bytes, bool $exception_on_missing_bytes = true): ? string
    // {
    //     if ($number_of_bytes < 0) {
    //         throw new \InvalidArgumentException();
    //     }
    //     $len = strlen($this->buf);
    //     if ($len < $number_of_bytes) {
    //         if ($exception_on_missing_bytes) {
    //             // is UnderflowException correct here?
    //             throw new \UnderflowException("{$number_of_bytes} byte(s) requested, only {$len} byte(s) available");
    //         } else {
    //             return null;
    //         }
    //     }
    //     return substr($this->buf, 0, $number_of_bytes);
    // }
    public function peekU8(bool $exception_on_missing_bytes = true): ? int
    {
        $blen = strlen($this->buf);
        if ($blen < 1) {
            if ($exception_on_missing_bytes) {
                // is UnderflowException appropriate here?
                throw new \UnderflowException();
            } else {
                return null;
            }
        }
        return from_uint8_t(substr($this->buf, 0, 1));
    }
    public function peekU16(bool $exception_on_missing_bytes = true): ? int
    {
        $blen = strlen($this->buf);
        if ($blen < 2) {
            if ($exception_on_missing_bytes) {
                throw new \UnderflowException();
            } else {
                return null;
            }
        }
        return from_little_uint16_t(substr($this->buf, 0, 2));
    }
    public function peekU32(bool $exception_on_missing_bytes = true): ? int
    {
        $blen = strlen($this->buf);
        if ($blen < 4) {
            if ($exception_on_missing_bytes) {
                throw new \UnderflowException();
            } else {
                return null;
            }
        }
        return from_little_uint16_t(substr($this->buf, 0, 2));
    }
    public function peek_string(bool $exception_on_missing_header = true, bool $exception_on_invalid_header = true): ? string
    {
        $blen = strlen($this->buf);
        $strlen = $this->peekU16($exception_on_missing_header);
        if ($strlen === null) {
            return null;
        }
        if (($blen - 2) < $strlen) {
            if ($exception_on_invalid_header) {
                throw new \UnderflowException();
            } else {
                return null;
            }
        }
        return substr($this->buf, 2, $strlen);
    }
    public function peek_position(bool $exception_on_missing_bytes = true): ? array
    {
        $blen = strlen($this->buf);
        if ($blen < 5) {
            if ($exception_on_missing_bytes) {
                throw new \UnderflowException();
            } else {
                return null;
            }
        }
        $tmp = new Tibia_binary_serializer(substr($this->buf, 0, 5));
        // i WOULD do this if order-of-execution was not important: return array('x' => $tmp->getU16(),'y' => $tmp->getU16(),'z' => $tmp->getU8());
        // but it is. if it fetches z first, the return values would be corrupted garbage data.
        $ret = array();
        $ret['x'] = $tmp->getU16();
        $ret['y'] = $tmp->getU16();
        $ret['z'] = $tmp->getU8();
        return $ret;
    }
    //</peek_functions>
}
