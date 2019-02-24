<?php
declare (strict_types = 1);
require_once('hhb_.inc.php');
require_once('hhb_datatypes.inc.php');
require_once('exphp.php');
class Player
{
    protected $ip;
    protected $port;
    protected $acc;
    protected $password;
    protected $charname;
    protected $socket;
    function __construct(string $host, int $port, string, string $password, string $charname)
    {
        $ip = gethostbyname($ip);
        if (false === filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new \RuntimeException("failed to get ip of hostname {$host}");
        }
        $this->ip = $ip;
        $this->port = $port;
        $this->acc = $acc;
        $this->password = $password;
        $this->charname = $charname;
        $this->login();
    }
    function __destruct()
    {
        if (is_resource($this->socket)) {
            $snd = static::hex('01 00 14');
            @socket_send($this->socket, $snd, strlen($snd), 0);
            @ex::socket_shutdown($this->socket, 2);
            ex::socket_close($this->socket);
        }
    }
    public function send(string $packet, bool $autoheader = true)
    {
        if ($autoheader) {
            $len = strlen($packet);
            if ($len > 65535) {
                throw new OutOfRangeException('Cannot autoheader a packet above 65535 bytes!');
            }
            $packet = to_little_uint16_t($len) . $packet;
            unset($len);
        }
        ex::socket_send($this->socket, $packet, strlen($packet), 0);
    }
    private function tibiastr(string $str) : string
    {
        $len = strlen($str);
        if ($len > 65535) {
            throw new OutOfRangeException('max length of a tibiastring is 65535 bytes! (i think..)');
        }
        return to_little_uint16_t($len) . $str;
    }
    public function walkSouth(int $steps = 1)
    {
        $packet = static::hex('01 00 67');
        $packet = str_repeat($packet, $steps);
        $this->send($packet, false);
    }
    public function walkDown(int $steps = 1)
    {
        $packet = static::hex('01 00 67');
        $packet = str_repeat($packet, $steps);
        $this->send($packet, false);
    }
    public function walkLeft(int $steps = 1)
    {
        $packet = static::hex('01 00 68');
        $packet = str_repeat($packet, $steps);
        $this->send($packet, false);
    }
    public function walkRight(int $steps = 1)
    {
        $packet = static::hex('01 00 66');
        $packet = str_repeat($packet, $steps);
        $this->send($packet, false);
    }
    public function walkUp(int $steps = 1)
    {
        $packet = static::hex('01 00 65');
        $packet = str_repeat($packet, $steps);
        $this->send($packet, false);
    }
    public function say(string $msg)
    {
        $packet = static::hex('9601') . $this->tibiastr($msg);
        $this->send($packet);
    }
    private function login()
    {
        $this->socket = ex::socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        ex::socket_set_block($this->socket);
		// contrary to PHP docs (saying that bind should be done before connect), OS is supposed to do this automatically: while(!socket_bind ( $this->socket, '0.0.0.0', mt_rand ( 1024, 5000 ) ));
        ex::socket_connect($this->socket, $this->ip, $this->port);
        $packet = static::hex('0A 03 37 F2 FF 07 00 66 75 63 6B 79 6F 75 19 00 78 58 35 38 34 38 4A 67 6A 72 49 45 70 6F 77 6F 4B 46 6B 66 72 69 72 47 4A 1C 00 6A 51 30 74 43 2F 71 51 65 68 6A 56 49 36 51 79 48 75 45 63 65 6B 67 49 31 70 6B 3D F6 02 00 ');
        $packet .= to_little_uint32_t($this->acc);
        $packet .= $this->tibiastr($this->charname);
        $packet .= $this->tibiastr($this->password);
        $packet .= static::hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00');
		// ???^
        $this->send($packet, true);
        $packet = static::hex('0400A00200010300814500030081450003008145000300814500');
		// ???^
        $this->send($packet, true);
        $buf = '';
		// ex::socket_recv ( $this->socket, $buf, 999, 0 );
		// hhb_var_dump ( ($buf) );
    }
    static function hex(string $hexstr) : string
    {
        $ret = trim(str_replace(' ', '', $hexstr));
        return hex2bin($ret);
    }
}
