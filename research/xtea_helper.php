<?php
declare (strict_types = 1);
require_once('hhb_datatypes.inc.php');
class Xtea_helper
{
    protected $helper_proc;
    /** @var FILE[2] $pipes stdin and stdout*/
    protected $pipes;
    protected $keys_binary;
    const ENCRYPT_COMMAND = 0;
    const DECRYPT_COMMAND = 1;
    function __construct(string $keys_binary)
    {
        if (strlen($keys_binary) !== 4 * 4) {
            throw new \InvalidArgumentException("wrong key length, must be 16 bytes.");
        }
        $this->keys_binary = $keys_binary;
        $descriptorspec = array(
            0 => array("pipe", "rb"),  // stdin 
            1 => array("pipe", "wb"),  // stdout
            // stderr: default behaviour: inherit and share the parent (our) stderr.
        );
        $cmd;
        if (false !== stripos(PHP_OS, 'cygwin')) {
            $cmd = './xtea_helper.exe';
        } elseif (false !== stripos(PHP_OS, 'windows')) {
            $cmd = 'xtea_helper.exe';
        } else {
            $cmd = './xtea_helper';
        }
        $this->helper_proc = proc_open($cmd, $descriptorspec, $this->pipes);
        if (false == $this->helper_proc) {
            throw new \RuntimeException("failed to start extea_helper! cmd: {$cmd}");
        }
        stream_set_blocking($this->pipes[0], true);
        stream_set_blocking($this->pipes[1], true);
        $this->sendMessage($keys_binary);
    }
    function __destruct()
    {
        fclose($this->pipes[0]);
        fclose($this->pipes[1]);
        proc_terminate($this->helper_proc);
        proc_close($this->helper_proc);
    }
    public function encrypt(string $data) : string
    {
        if ((($len = strlen($data)) % 8) !== 0) {
            // needs length padding
            $nearest = (int)(ceil($len / 8) * 8);
            $data .= str_repeat("p", $nearest - $len);
        } elseif ($len === 0) {
            $data = str_repeat("p", 8);
        }
        $message = chr($this::ENCRYPT_COMMAND) . to_little_uint16_t(strlen($data)) . $data;
        $this->sendMessage($message);
        $ret = $this->readMessage();
        return $ret;
    }
    public function decrypt(string $data) : string
    {
        if ((($len = strlen($data)) % 8) !== 0) {
            // needs length padding
            $nearest = (int)(ceil($len / 8) * 8);
            $data .= str_repeat("\x00", $nearest - $len);
        } elseif ($len === 0) {
            $data = str_repeat("\x00", 8);
        }
        $message = chr($this::DECRYPT_COMMAND) . to_little_uint16_t(strlen($data)) . $data;
        $this->sendMessage($message);
        return $this->readMessage();
    }
    protected function sendMessage(string $message) : void
    {
        fwrite($this->pipes[0], to_little_uint16_t(strlen($message)) . $message);
    }
    protected function readMessage()
    {
        $size = fread($this->pipes[1], 2);
        $size = from_little_uint16_t($size);
        $ret = fread($this->pipes[1], $size);
        return $ret;
    }
}