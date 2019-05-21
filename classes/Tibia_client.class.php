<?php
declare (strict_types = 1);
require_once('../libs/hhb_.inc.php'); // https://github.com/divinity76/hhb_.inc.php/blob/master/hhb_.inc.php
require_once('../libs/hhb_datatypes.inc.php'); // https://github.com/divinity76/hhb_.inc.php/blob/master/hhb_datatypes.inc.php
require_once('../libs/XTEA.class.php'); // https://github.com/divinity76/php-xtea/blob/master/src/xtea.class.php
require_once('../classes/Tibia_binary_serializer.class.php');

class Tibia_client
{
    /** @var Tibia_client_internal $internal */
    public $internal;
    function __construct(string $host, int $port, string $account, string $password, string $charname, bool $debugging = false)
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
        $packet->addU8($type)->add_string($message);
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
    const TIBIA_VERSION_INT = 1097;
    const TIBIA_VERSION_STRING = "10.97";
    // CLIENTOS_WINDOWS - it would be a major task to actually support emulating different OSs, they have different login protocols,
    // so for simplicity, we always say we're the Windows client.
    const TIBIA_CLIENT_OS_INT = 4;
    const TIBIA_CLIENT_OS_STRING = 'CLIENTOS_WINDOWS';
    const RSA_PUBLIC_KEY =
    "-----BEGIN PUBLIC KEY-----\n" .
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbZGkDtFsHrJVlaNhzU71xZROd\n" .
        "15QHA7A+bdB5OZZhtKg3qmBWHXzLlFL6AIBZSQmIKrW8pYoaGzX4sQWbcrEhJhHG\n" .
        "FSrT27PPvuetwUKnXT11lxUJwyHFwkpb1R/UYPAbThW+sN4ZMFKKXT8VwePL9cQB\n" .
        "1nd+EKyqsz2+jVt/9QIDAQAB\n" .
        "-----END PUBLIC KEY-----\n"; // yes it is supposed to end with an \n according to openssl.
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
    /** @var string $xtea_key_binary */
    protected $xtea_key_binary; //CS-random-generated for each instance. unless $debugging
    /** @var int[4] $xtea_key_intarray */
    protected $xtea_key_intarray;
    function __construct(string $host, int $port, string $account, string $password, string $charname, bool $debugging = false)
    {
        if (strlen($account) < 1) {
            throw new \InvalidArgumentException("account name cannot be empty (TFS's implementation of the protocol REQUIRES a non-empty account name, even tho the tibia protocol itself technically does not.)");
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
        //
        {
            $this->public_key_parsed_cache = openssl_pkey_get_public($this::RSA_PUBLIC_KEY);
            if (false === $this->public_key_parsed_cache) {
                $err = openssl_error_string();
                throw new \RuntimeException("openssl_pkey_get_public() failed: {$err}");
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
        if (!!$this->public_key_parsed_cache) {
            openssl_pkey_free($this->public_key_parsed_cache);
        }
    }
    /**
     * little-endian adler32
     * (the Adler specs demands big-endian, but Cipsoft decided 
     * "screw the rules, i have green hair" and implemented a little-endian Adler for the Tibia protocol, douchebags.)
     *
     * @param string $data
     * @return string binary
     */
    public static function Adler32le(string $data): string
    {
        return strrev(hash('adler32', $data, true));
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
        }
        // 
        {
            $data = new Tibia_binary_serializer();
            $data->add("\x00"); // "protocol id byte", i guess it's different for login protocol / game protocol / status protocol / etc, but seems to be ignored by TFS
            $data->addU16($this::TIBIA_CLIENT_OS_INT);
            $data->addU16($this::TIBIA_VERSION_INT);
            $data->add(str_repeat("\x00", 7)); // > msg.skipBytes(7); // U32 client version, U8 client type, U16 dat revision
            $rsa_data = new Tibia_binary_serializer();
            $rsa_data->add("\x00"); // uhh... RSA decryption verification byte? (TFS considers the RSA decryption a success if this is 0 AFTER decryption.)
            {
                //<xtea_initialization>
                if ($this->debugging) {
                    // nice keys for debugging (but insecure)
                    $this->xtea_key_binary = (new Tibia_binary_serializer())->add_string("xtea_key_12345")->str();
                    $this->xtea_key_binary = str_repeat((new Tibia_binary_serializer())->addU32(1337)->str(), 4);
                    $this->xtea_key_binary = str_repeat("\x00", 4 * 4);
                } else {
                    // secure key, not good for debugging.
                    $this->xtea_key_binary = random_bytes(4 * 4);
                }
                assert(strlen($this->xtea_key_binary) === (4 * 4));
                $this->xtea_key_intarray = XTEA::binary_key_to_int_array($this->xtea_key_binary, XTEA::PAD_NONE);
                assert(count($this->xtea_key_intarray) === 4);
                //</xtea_initialization>
            }
            $rsa_data->add($this->xtea_key_binary);
            $rsa_data->add("\x00"); // gamemaster flag (back in tibia 7.6 it was 0 for regular players and 2 for GMs iirc. TFS ignores it.)
            $firstPacket = new Tibia_binary_serializer($this->read_next_packet(true, true, false, false));
            if ($firstPacket->size() !== 12) {
                throw new \LogicException("first packet was not 12 bytes! .... " . $firstPacket->size());
            }
            $firstPacket->eraseX(7); //TODO: what are these 7 skipped bytes? i don't know.
            $challengeTimestamp = $firstPacket->getU32();
            $challengeRandom = $firstPacket->getU8();
            assert(0 === $firstPacket->size());
            $session_data = implode("\n", array(
                $this->account,
                $this->password,
                '???what is this token???',
                ((string)time()) // ??token time??
            ));
            $rsa_data->add_string($session_data);
            $rsa_data->add_string($this->charname);
            $rsa_data->addU32($challengeTimestamp);
            $rsa_data->addU8($challengeRandom);
            $data->add($this->RSA_encrypt($rsa_data->str()));
            $this->send($data->str(), true, true, false);
            // if we don't sleep a little after logging in, nothing will work, talking, walking, etc won't respond for the first
            // few milliseconds or so. (???)
            usleep(100 * 1000);
            $this->ping(); // because why not..
        }
    }

    /**
     * read next packet
     * if $wait_for_packet is false and no packet is available, NULL is returned.
     * if $remove_size_header is false, a 0-byte packet (packet only having a size header for 0 bytes) will result in an empty string. (ping packet? TCP_KEEPALIVE packet?)
     * if $remove_adler_checksum is true, the checksum will be removed from the returned data (after being verified - if verification fails, it's not considered an adler checksum)
     * if $xtea_decrypt is true, the data after the adler checksum will be xtea-decrypted. (if the length OR adler checksum is wrong, it's not considered xtea-encrypted.)
     *
     * @param boolean $wait_for_packet
     * @param boolean $remove_size_header
     * @param boolean $remove_adler_checksum
     * @param boolean $xtea_decrypt
     * @return string|null
     */
    public function read_next_packet(bool $wait_for_packet, bool $remove_size_header = true, bool $remove_adler_checksum = true, bool $xtea_decrypt = true, bool &$adler_removed = null, bool &$xtea_decrypted = null): ?string
    {
        if ($xtea_decrypt && !$remove_adler_checksum) {
            throw new \InvalidArgumentException(
                "if \$xtea_decrypt is on, then \$remove_adler_checksum must also be on " .
                    " (i cba writing the code required to handle that configuration right now, and the code would come with a performance penalty "
                    . "for the common cases as well..)"
            );
        }
        if ($xtea_decrypt && !$remove_size_header) {
            throw new \InvalidArgumentException(
                "if \$xtea_decrypt is on, then \$remove_size_header must be on too " .
                    "(it's possible to fix this, but considering that the xtea scheme includes a decrypted inner_length too, " .
                    "i believe the outer size header isn't useful anyway when xtea-decrypting...)"
            );
        }
        $xtea_decrypted = false;
        $adler_removed = false;
        $flag = ($wait_for_packet ? MSG_WAITALL : MSG_DONTWAIT);
        $read = '';
        $buf = '';
        // 2 bytes: tibia packet size header, little-endian uint16
        $ret = socket_recv($this->socket, $buf, 2, $flag);
        if ($ret === 0 || ($ret === false && socket_last_error($this->socket) === SOCKET_EWOULDBLOCK)) { // 11: resource temporarily unavailable
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
        if (strlen($read) === 0) {
            // ping packet or TCP_KEEPALIVE packet or something i think?
            return "";
        }
        if ($remove_adler_checksum && strlen($read) >= 4) {
            $offset = ($remove_size_header ? 0 : 2);
            $checksum = substr($read, $offset, 4);
            $checksummed_data = substr($read, $offset + 4);
            if (self::Adler32le($checksummed_data) === $checksum) {
                $adler_removed = true;
                $read = substr($read, 0, $offset) . $checksummed_data;
            } else {
                // unexpected, adler checksum verification failed..
            }
            unset($offset, $checksum, $checksummed_data);
        }

        if ($xtea_decrypt && $adler_removed) {
            do {
                $offset = ($remove_size_header ? 0 : 2);
                $to_decrypt = substr($read, $offset);
                if (strlen($to_decrypt) < 8 || ((strlen($to_decrypt) % 8) !== 0)) {
                    // this packet cannot be xtea-encrypted, wrong length. however, still weird considering the adler checksum was verified..
                    break;
                }
                $decrypted = XTEA::decrypt_unsafe($to_decrypt, $this->xtea_key_intarray, 32);
                $inner_length = from_little_uint16_t(substr($decrypted, 0, 2));
                if (strlen($decrypted) < ($inner_length + 2)) {
                    // not xtea-encrypted, wrong inner_length, however weird because the checksum was verified AND the length was correct. all conicidences?
                    break;
                }
                $decrypted = substr($decrypted, 2, $inner_length); // 2: remove inner_length header - $inner_length: remove padding bytes (if any)
                $read = substr($read, 0, $offset) . $decrypted;
                $xtea_decrypted = true;
            } while (false);
            unset($offset, $to_decrypt, $decrypted);
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
     * *DEPRECATED* you should probably use Tibia_binary_serializer()->get_string() instead.
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
        return (new Tibia_binary_serializer($bytes))->get_string(false, false);
    }
    const POSITION_SIZE_BYTES = 5;
    // *DEPRECATED* you should probably use Tibia_binary_serializer()->get_position() instead.
    public static function parse_position(string $bytes): ?array
    {
        return (new Tibia_binary_serializer($bytes))->get_position(false);
    }
    // *DEPRECATED* you should probably use Tibia_binary_serializer()->add_string() instead.
    public function tibia_str(string $str): string
    {
        return (new Tibia_binary_serializer())->add_string($str)->str();
    }
    // openssl api has 3 different standarized padding schemes for RSA, and obviously cipsoft went all "NIH" and made their own
    public /*static*/ function cipsoft_rsa_pad(string &$data): void
    {
        if ((($len = strlen($data)) % 128) === 0) {
            return;
        }
        $nearest = (int)(ceil($len / 128) * 128);
        assert($nearest !== $len);
        assert($nearest > $len);
        if ($this->debugging) {
            $data .= str_repeat("\x00", $nearest - $len);
        } else {
            // a security-focused implementation would use CS random_bytes() instead of str_repeat. (and i think Cipsoft is doing that too.)
            $data .= random_bytes($nearest - $len);
        }
        return;
    }
    public function RSA_encrypt(string $data): string
    {
        assert(!!$this->public_key_parsed_cache);
        $crypted = '';
        /// openssl padding schemes: OPENSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING.
        // openssl api has 3 different standarized padding schemes for RSA, and obviously cipsoft invented it's own incompatible one.
        $this->cipsoft_rsa_pad($data);
        assert((strlen($data) % 128) === 0);
        $res = openssl_public_encrypt($data, $crypted, $this->public_key_parsed_cache, OPENSSL_NO_PADDING);
        if (false === $res) {
            $err = openssl_error_string();
            throw new \RuntimeException("openssl_public_encrypt() failed: {$err}");
        }
        return $crypted;
    }
    protected function logout(): void
    {
        try {
            $this->send("\x14");
            // TFS bug? if we send the disconnect request too fast before closing the socket,
            // the server will not log out the actual avatar..
            //usleep(50000*1000);
            while ($this->read_next_packet(false, false, false, false) !== null) {
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
    public function send(string $packet, bool $add_size_header = true, bool $add_adler_checksum = true, bool $xtea_encrypt = true): void
    {
        if ($xtea_encrypt) {
            $packet = XTEA::encrypt((new Tibia_binary_serializer())->add_string($packet)->str(), $this->xtea_key_intarray, ($this->debugging ? XTEA::PAD_0x00 : XTEA::PAD_RANDOM));
        }
        if ($add_adler_checksum) {
            $packet = $this->Adler32le($packet) . $packet;
        }
        if ($add_size_header) {
            $len = strlen($packet);
            if ($len > 65535) {
                // note that it's still possible to have several separate packets each individually under 65535 bytes, 
                // concantenated with the Nagle-algorithm but then you have to add the size headers and adler checksums manually, 
                // before calling send()
                throw new OutOfRangeException('Cannot automatically add size header a to a packet above 65535 bytes!');
            }
            $packet = (new Tibia_binary_serializer())->add_string($packet)->str();
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

    public static function parse_packet(string $packet, bool $size_header_removed = true, bool $adler_checksum_removed = true, bool $xtea_decrypted = true): Tibia_client_packet_parsed
    {
        // for now i cba writing stuff to handle size header / adler checksum / xtea encryption in here...
        if (!$size_header_removed) {
            throw new \InvalidArgumentException("remove size header before calling this function.");
        }
        if (!$adler_checksum_removed) {
            throw new \InvalidArgumentException("remove adler checksum before calling this function.");
        }
        if (!$xtea_decrypted) {
            throw new \InvalidArgumentException("decrypt xtea before calling this function.");
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
        $packet = new Tibia_binary_serializer($packet);
        $ret->type = $packet->getU8();
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
                    $packet = $packet->str();
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
                    // idk what statement_id is either.. my best guess: some weird server-global talk id used by cipsoft for debugging
                    $ret->data["statement_id"] = $packet->getU32();
                    $ret->data['speaker_name'] = $packet->get_string();
                    $ret->data['speaker_level'] = $packet->getU16();
                    $ret->data['speak_type'] = $packet->getU8();
                    $ret->data['speaker_position'] = $packet->get_position();
                    $ret->data['text'] = $packet->get_string();
                    // Tell packet parser that your done, 
                    // if it disagrees with you, there is still data in packet.
                    // And it will give you a warning
                    $ret->warnings = $packet->im_done($ret->warnings, $ret->type_name);
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
    public $adler_checksum_removed = true;
    public $xtea_decrypted = true;
    public $bytes_hex = "";
    public $data = [];
    public $errors = [];
    public $warnings = [];
}
