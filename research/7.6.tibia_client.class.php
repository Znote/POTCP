<?php
declare (strict_types = 1);
// 7.6 protocol version of Tibia_Client
// WARNING: this file is unmaintained and incompatible with the other Tibia_Client 
// (mostly compatible but with differences, for example Tibia_Client_Internal::send() takes only 2 arguments, rather than the 4x that 10.x version takes)
require_once('../libs/hhb_.inc.php'); // https://github.com/divinity76/hhb_.inc.php/blob/master/hhb_.inc.php
require_once('../classes/Tibia_binary_serializer.class.php');
class Tibia_client
{
    /** @var Tibia_client_internal $internal */
    public $internal;
    function __construct(string $host, int $port, int $account, string $password, string $charname, bool $debugging = false)
    {
        $this->internal = new Tibia_client_internal($host, $port, $account, $password, $charname, $debugging);
        $this->internal->tibia_client = $this;
    }
    function __destruct()
    {
        unset($this->internal); // trying to force it to destruct now, this would be the appropriate time.
    }
    /**
     * ping the server
     * important to do this periodically, because if you don't, the server
     * will consider the connection broken, and kick you!
     *
     * @return void
     */
    public function ping(): void
    {
        $this->internal->ping();
    }
    const TALKTYPE_SAY = 1;
    const TALKTYPE_WHISPER = 2;
    const TALKTYPE_YELL = 3;
    const TALKTYPE_BROADCAST = 13;
    const TALKTYPE_MONSTER_SAY = 36;
    const TALKTYPE_MONSTER_YELL = 37;
    public function say(string $message, int $type = self::TALKTYPE_SAY): void
    {
        if (strlen($message) > 255) {
            throw new InvalidArgumentException(
                "message cannot be longer than 255 bytes! (PS: this is not a tibia protocol limitation, but a TFS limitation, " .
                    "the protocol limitation is actually close to 65535 bytes.)"
            );
        }
        if ($type < 0 || $type > 255) {
            throw new \InvalidArgumentException(
                "type must be between 0-255! " .
                    "(also it can't be private-message or channel-message talk type but i cba writing the code to detect it right now)"
            );
        }
        $packet = new Tibia_binary_serializer("\x96"); // 0x96: talk packet
        $packet->addU8($type);
        $packet->add_string($message);
        $this->internal->send($packet->str());
    }
    // alias of walk_north
    public function walk_up(int $steps = 1): void
    {
        $this->walk_north($steps);
    }
    public function walk_north(int $steps = 1): void
    {
        //todo: invalidargumentexception < 0
        //optimization note: steps can be concatenated nagle-style and issued in a single packet
        for ($i = 0; $i < $steps; ++$i) {
            $this->internal->send("\x65");
        }
    }
    // alias of walk_east
    public function walk_right(int $steps = 1): void
    {
        $this->walk_east($steps);
    }
    public function walk_east(int $steps = 1): void
    {
        //todo: invalidargumentexception < 0
        //optimization note: steps can be concatenated nagle-style and issued in a single packet
        for ($i = 0; $i < $steps; ++$i) {
            $this->internal->send("\x66");
        }
    }
    // alias of walk_south
    public function walk_down(int $steps = 1): void
    {
        $this->walk_south($steps);
    }
    public function walk_south(int $steps = 1): void
    {
        //todo: invalidargumentexception < 0
        //optimization note: steps can be concatenated nagle-style and issued in a single packet
        for ($i = 0; $i < $steps; ++$i) {
            $this->internal->send("\x67");
        }
    }
    // alias of walk_west
    public function walk_left(int $steps = 1): void
    {
        $this->walk_west($steps);
    }
    public function walk_west(int $steps = 1): void
    {
        //todo: invalidargumentexception < 0
        //optimization note: steps can be concatenated nagle-style and issued in a single packet
        for ($i = 0; $i < $steps; ++$i) {
            $this->internal->send("\x68");
        }
    }
    public function dance(int $moves = 10, int $msleep = 100)
    {
        //  case 0x6F: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_NORTH); break;
        //	case 0x70: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_EAST); break;
        //	case 0x71: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_SOUTH); break;
        //	case 0x72: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_WEST); break;
        $direction_bytes = "\x6F\x70\x71\x72";
        $blen = strlen($direction_bytes) - 1;
        $last = null;
        for ($i = 0; $i < $moves; ++$i) {
            do {
                $neww = rand(0, $blen);
            } while ($neww === $last);
            $last = $neww;
            $this->internal->send($direction_bytes[$neww]);
            usleep($msleep * 1000);
        }
    }
}
class Tibia_client_internal
{
    const TIBIA_VERSION_INT = 760;
    const TIBIA_VERSION_STRING = "7.6";
    // CLIENTOS_WINDOWS - it would be a major task to actually support emulating different OSs, they have different login protocols,
    // so for simplicity, we always say we're the Windows client.
    const TIBIA_CLIENT_OS_INT = 4;
    const TIBIA_CLIENT_OS_STRING = 'CLIENTOS_WINDOWS';
    /** @var Tibia_client|NULL $tibia_client */
    public $tibia_client;
    protected $public_key_parsed_cache = null;
    public $debugging = false;
    protected $ip;
    protected $port;
    protected $account;
    protected $password;
    public $charname;
    protected $socket;
    function __construct(string $host, int $port, int $account, string $password, string $charname, bool $debugging = false)
    {
        if ($account < 0) {
            throw new \InvalidArgumentException("account MUST be >= 0 (and <= 0xFFFFFFFF)");
        }
        if ($account > 0xFFFFFFFF) {
            throw new \InvalidArgumentException("account MUST be <= 0xFFFFFFFF (and >= 0)");
        }
        $ip = $host;
        if (false === filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = gethostbyname($ip);
            if (false === filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new \RuntimeException("failed to get ip of hostname {$host}");
            }
            if (false === filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                throw new \RuntimeException("could only find an ipv6 address for that host, ipv6 support is (not yet?) implemented!");
            }
        }
        $this->ip = $ip;
        $this->port = $port;
        $this->account = $account;
        $this->password = $password;
        $this->charname = $charname;
        $this->debugging = $debugging;
        $this->login();
    }
    function __destruct()
    {
        $this->logout();
    }
    protected function login(): void
    {
        if (!!$this->socket) {
            throw new \LogicException("socket already initialized during login()! ");
        }
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if (false === $this->socket) {
            $err = socket_last_error();
            throw new \RuntimeException("socket_create(AF_INET, SOCK_STREAM, SOL_TCP) failed! {$err}: " . socket_strerror($err));
        }
        if (!socket_set_block($this->socket)) {
            $err = socket_last_error($this->socket);
            throw new \RuntimeException("socket_set_block() failed! {$err}: " . socket_strerror($err));
        }
        if (!socket_connect($this->socket, $this->ip, $this->port)) {
            $err = socket_last_error($this->socket);
            throw new \RuntimeException("socket_connect() failed! {$err}: " . socket_strerror($err));
        }
        if (!socket_set_option($this->socket, SOL_TCP, TCP_NODELAY, 1)) {
            // this actually avoids some bugs, espcially if you try to talk right after login, 
            // won't work with TCP_NODELAY disabled, but will work with TCP_NODELAY enabled.
            // (why? not sure.)
            $err = socket_last_error($this->socket);
            throw new \RuntimeException("setting TCP_NODELAY failed! {$err}: " . socket_strerror($err));
        } {
            $packet = new Tibia_binary_serializer();
            $packet->addU16(522); // 522: game-server connection
            $packet->addU8($this::TIBIA_CLIENT_OS_INT);
            $packet->addU16($this::TIBIA_VERSION_INT);
            $packet->addU8(0); // gamemaster flag, probably?
            $packet->addU32($this->account);
            $packet->add_string($this->charname);
            $packet->add_string($this->password);

            $this->send($packet->str(), true);
            // if we don't sleep a little after logging in, nothing will work, talking, walking, etc won't respond for the first
            // few milliseconds or so. (???)
            usleep(100 * 1000);
            //$this->ping(); // because why not..
        }
    }
    /**
     * read next packet
     * if $wait_for_packet is false and no packet is available, NULL is returned.
     * if $remove_size_header is false, a 0-byte packet (packet only having a size header for 0 bytes) will result in an empty string. (ping packet? TCP_KEEPALIVE packet?)
     *
     * @param boolean $wait_for_packet
     * @param boolean $remove_size_header
     * @return string|null
     */
    public function read_next_packet(bool $wait_for_packet, bool $remove_size_header = true): ?string
    {
        $flag = ($wait_for_packet ? MSG_WAITALL : MSG_DONTWAIT);
        $read = '';
        $buf = '';
        // 2 bytes: tibia packet size header, little-endian uint16
        $ret = socket_recv($this->socket, $buf, 2, $flag);
        if ($ret === 0 || ($ret === false && socket_last_error($this->socket) === SOCKET_EWOULDBLOCK)) {
            // no new packet available
            if (!$wait_for_packet) {
                // .. and we're not waiting.
                return null;
            }
            // FIXME socket_recv timed out even with MSG_WAITALL (it's a socksetopt option to change the timeout)
            return null;
        }
        if ($ret === false) {
            // ps: recv error at this stage probably did not corrupt the recv buffer. (unlike in the rest of this function)
            $erri = socket_last_error($this->socket);
            $err = socket_strerror($erri);
            throw new \RuntimeException("socket_recv error {$erri}: {$err}");
        }
        assert(strlen($buf) >= 1);
        $read .= $buf;
        $buf = '';
        if ($ret === 1) {
            // ... we have HALF a size header, wait for the other half regardless of $wait_for_packet (it should come ASAP anyway)
            // (if we don't, then the buffer is in a corrupt state where next read_next_packet will read half a size header!
            //  - another way to handle this would be to use MSG_PEEK but oh well)
            $ret = socket_recv($this->socket, $buf, 1, MSG_WAITALL);
            if ($ret === false) {
                $erri = socket_last_error($this->socket);
                $err = socket_strerror($erri);
                throw new \RuntimeException("socket_recv error {$erri}: {$err} - also: the recv buffer is now in a corrupted state, " .
                    "you should throw away this instance of TibiaClient and re-login (this should never happen btw, you probably have a very unstable connection " .
                    "or a bugged server or something)");
            }
            if ($ret !== 1) {
                throw new \RuntimeException("even with MSG_WAITALL we could only read half a size header! the recv buffer is now in a corrupted state, " .
                    "you should throw away this instance of TibiaClient and re-login (this should never happen btw, you probably have a very unstable connection " .
                    "or a bugged server or something)");
            }
            assert(1 === strlen($buf));
            $read .= $buf;
            $buf = '';
        }
        assert(2 === strlen($read));
        assert(0 === strlen($buf));
        $size = from_little_uint16_t($read);
        while (0 < ($remaining = (($size + 2) - strlen($read)))) {
            $buf = '';
            $ret = socket_recv($this->socket, $buf, $remaining, MSG_WAITALL);
            if ($ret === false) {
                $erri = socket_last_error($this->socket);
                $err = socket_strerror($erri);
                throw new \RuntimeException("socket_recv error {$erri}: {$err} - also: the recv buffer is now in a corrupted state, " .
                    "you should throw away this instance of TibiaClient and re-login (this should never happen btw, you probably have a very unstable connection " .
                    "or a bugged server or something)");
            }
            if (0 === $ret) {
                throw new \RuntimeException("even with MSG_WAITALL and trying to read {$remaining} bytes, socket_recv return 0! something is very wrong. " .
                    "also the recv buffer is now in a corrupted state, you should throw away this instance of TibiaClient and re-login. " .
                    "(this should never happen btw, you probably have a very unstable connection " .
                    "or a bugged server or something)");
            }
            $read .= $buf;
        }
        if ($remaining !== 0) {
            throw new \LogicException("...wtf, after the read loop, remaining was: " . hhb_return_var_dump($remaining) . " - should never happen, probably a code bug.");
        }
        if (strlen($read) !== ($size + 2)) {
            throw new \LogicException('...wtf, `strlen($read) === ($size + 2)` sanity check failed, should never happen, probably a code bug.');
        }
        assert(strlen($read) >= 2);
        if ($remove_size_header) {
            $read = substr($read, 2);
        }
        return $read;
    }
    /**
     * ping the server
     * important to do this periodically, because if you don't, the server
     * will consider the connection broken, and kick you!
     *
     * @return void
     */
    public function ping(): void
    {
        $this->send("\x1E");
    }
    /**
     * parse tibia_str
     * if it is a valid tibia_str, returns the tibia str, length header and trailing bytes removed.
     * if it's *not* a valid tibia_str, returns null
     * a tibia_str may be binary.
     *
     * @param string $bytes
     * @param integer $offset
     * @return string|null
     */
    public static function parse_tibia_str(string $bytes): ?string
    {
        $len = strlen($bytes);
        if ($len < 2) {
            // not a tibia_str.
            return null;
        }
        $claimed_len = from_little_uint16_t(substr($bytes, 0, 2));
        if ($len < ($claimed_len + 2)) {
            // not a tibia_str.
            return null;
        }
        // valid tibia_str. (even if it has trailing bytes, which are ignored.)
        $ret = substr($bytes, 2, $claimed_len);
        return $ret;
    }
    const POSITION_SIZE_BYTES = 5;
    public static function parse_position(string $bytes): ?array
    {
        $len = strlen($bytes);
        if ($len < self::POSITION_SIZE_BYTES) {
            return null;
        }
        $ret = array();
        $ret['x'] = from_little_uint16_t(substr($bytes, 0, 2));
        $ret['y'] = from_little_uint16_t(substr($bytes, 2, 2));
        $ret['z'] = from_uint8_t(substr($bytes, 4, 1));
        return $ret;
    }
    public function tibia_str(string $str): string
    {
        $len = strlen($str);
        if ($len > 65535) {
            throw new OutOfRangeException('max length of a tibia_str is 65535 bytes! (i think..)');
        }
        return to_little_uint16_t($len) . $str;
    }
    protected $is_logged_out = false;
    public function logout_force()
    {
        $this->logout();
    }
    protected function logout(): void
    {
        if ($this->is_logged_out) {
            return;
        }
        $this->is_logged_out = true;
        try {
            $this->send("\x14");
            // TFS bug? if we send the disconnect request too fast before closing the socket,
            // the server will not log out the actual avatar..
            //usleep(50000*1000);
            while ($this->read_next_packet(false, false) !== null) {
                //...
            }
            $this->send("\x0F");
            usleep(100 * 1000);
        } finally {
            if ($this->socket) {
                socket_close($this->socket);
            }
        }
    }
    public function send(string $packet, bool $add_size_header = true): void
    {
        if ($add_size_header) {
            $len = strlen($packet);
            if ($len > 65535) {
                // note that it's still possible to have several separate packets each individually under 65535 bytes, 
                // concantenated with the Nagle-algorithm but then you have to add the size headers and adler checksums manually, 
                // before calling send()
                throw new OutOfRangeException('Cannot automatically add size header a to a packet above 65535 bytes!');
            }
            $packet = to_little_uint16_t($len) . $packet;
        }
        $this->socket_write_all($this->socket, $packet);
    }
    /**
     * writes ALL data to socket, and throws an exception if that's not possible.
     *
     * @param socket $socket
     * @param string $data
     * @return void
     */
    public static function socket_write_all($socket, string $data): void
    {
        if (!($dlen = strlen($data))) {
            return;
        }
        do {
            assert($dlen > 0);
            assert(strlen($data) === $dlen);
            $sent_now = socket_write($socket, $data);
            if (false === $sent_now) {
                $err = socket_last_error($socket);
                throw new \RuntimeException("socket_write() failed! {$err}: " . socket_strerror($err));
            }
            if (0 === $sent_now) {
                // we'll try *1* last time before throwing exception...
                $sent_now = socket_write($socket, $data);
                if (false === $sent_now) {
                    $err = socket_last_error($socket);
                    throw new \RuntimeException("socket_write() failed after first returning zero! {$err}: " . socket_strerror($err));
                }
                if (0 === $sent_now) {
                    // something is very wrong but it's not registering as an error at the kernel apis...
                    throw new \RuntimeException("socket_write() keeps returning 0 bytes sent while {$dlen} byte(s) to send!");
                }
            }
            $dlen -= $sent_now;
            $data = substr($data, $sent_now);
        } while ($dlen > 0);
        assert($dlen === 0);
        assert(strlen($data) === 0);
        // all data sent.
        return;
    }
    public static function parse_packet(string $packet, bool $size_header_removed = true): Tibia_client_packet_parsed
    {
        // for now i cba writing stuff to handle size header / adler checksum / xtea encryption in here...
        if (!$size_header_removed) {
            throw new \InvalidArgumentException("remove size header before calling this function.");
        }
        $ret = new Tibia_client_packet_parsed();
        $ret->bytes_hex = bin2hex($packet);
        $len = strlen($packet);
        if ($len === 0) {
            // uhhh....
            $ret->type = 0;
            $ret->type_name = "ping_0_bytes"; // ping_tcp_keepalive ? 
            return $ret;
        }
        $ret->type = from_uint8_t(substr($packet, 0, 1));
        $packet = substr($packet, 1);
        switch ($ret->type) {
            case 0x0D: {
                    // seems to be either ping or ping_request (eg a request that we ping back)
                    $ret->type_name = "ping_0x0D";
                    return $ret;
                    break;
                }
            case 0x17: {
                    // TODO: better parsing of this packet, which is a big task (this packet is very very complex for some reason.)
                    $ret->type_name = "login_and_map_and_welcome";
                    $welcome_messages = [];
                    $found = 0;
                    $ret->data['welcome_messages'] = [];
                    for ($i = strlen($packet); $i > 0; --$i) {
                        $str = Tibia_client_internal::parse_tibia_str(substr($packet, $i));
                        if (null === $str) {
                            continue;
                        }
                        if (strlen($str) < 1) {
                            continue;
                        }
                        if (strlen($str) !== strcspn($str, "\x00\x01")) {
                            continue;
                        }
                        // PROBABLY found the message. 
                        ++$found;
                        $ret->data['welcome_messages'][] = ($str);
                        if ($found >= 2) {
                            break;
                        }
                    }
                    return $ret;
                    break;
                }
            case Tibia_client_packet_parsed::TYPE_SAY: // 0xAA
                {
                    $ret->type_name = "TYPE_SAY";
                    // This serializer will do packet parse cleanups for us
                    $sub_packet = new Tibia_binary_serializer($packet);
                    $ret->data['speaker_name'] = $sub_packet->get_string();
                    $ret->data['speak_type'] = $sub_packet->getU8();
                    $ret->data['speaker_position'] = $sub_packet->get_position();
                    $ret->data['text'] = $sub_packet->get_string();
                    // Tell packet parser that your done, 
                    // if it disagrees with you, there is still data in packet.
                    // And it will give you a warning
                    if (!strlen($sub_packet->str())) {
                        $ret->warnings[] = "extra bytes: " . bin2hex($sub_packet->str());
                    }
                    return $ret;
                    unset($strlen);
                    break;
                }
            default: {
                    $ret->type_name = "unknown 0x" . bin2hex(to_uint8_t($ret->type));
                    return $ret;
                    break;
                }
        }
        // ...unreachable?
        return $ret;
    }
}
class Tibia_client_packet_parsed
{
    const TYPE_SAY = 0xAA;
    /** @var u8 $type */
    public $type;
    /** @var string $type_name */
    public $type_name = "unknown";
    public $size_header_removed = true;
    public $bytes_hex = "";
    public $data = [];
    public $errors = [];
    public $warnings = [];
}
