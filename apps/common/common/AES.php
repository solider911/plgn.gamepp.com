<?php
/**
 * Created by PhpStorm.
 * User: duanwujie
 * Date: 2016/2/29
 * Time: 18:43
 */
namespace app\common\common;

class AES {

    private $key = ''; #Same as in JAVA
    private $hex_iv = ''; # converted JAVA byte code in to HEX and placed it here

    function __construct() {
        $this->key = "1234567890123456";
        $this->hex_iv = "0000000000000000";
//        $this->key = hash('sha256', $this->key, true);
        //echo $this->key.'<br/>';
    }

    // 加密
    function encrypt($str) {
        //open module
        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $this->hex_iv);
        mcrypt_generic_init($module, $this->key, $this->hex_iv);

        // padding
        $block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $pad = $block - (strlen($str) % $block);
        $str .= str_repeat(chr($pad), $pad);
        //encrypt
        $encrypted = mcrypt_generic($module, $str);

        //Close
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        return base64_encode($encrypted);
    }

    // 解密
    function decrypt($code) {
        //Open module
        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $this->hex_iv);
        mcrypt_generic_init($module, $this->key, $this->hex_iv);

        // decrypt
        $str = mdecrypt_generic($module, base64_decode($code));

        // close
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);

        return $str;
    }


    /**
     * ecb模式加密
     */
    function encrypt_ecb($input){
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
        $input = $this->addpadding($input, $size);
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $iv = mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $this->key, $iv);
        $data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        $data = $this->base64url_encode($data);
        return $data;
    }

    /**
     * ecb模式解密
     */
    function decrypt_ecb($sStr){
        $decrypted= mcrypt_decrypt(
            MCRYPT_RIJNDAEL_128,
            //$sKey,
            $this->key,
            //base64_decode($sStr),
            $this->base64url_decode($sStr),
            //$sStr,
            MCRYPT_MODE_ECB
        );
        $dec_s = strlen($decrypted);
        $padding = ord($decrypted[$dec_s-1]);
        $decrypted = substr($decrypted, 0, -$padding);
        return $decrypted;
    }



    /*
      For PKCS7 padding
     */
    private function addpadding($string, $blocksize = 16) {
        $len = strlen($string);
        $pad = $blocksize - ($len % $blocksize);
        $string .= str_repeat(chr($pad), $pad);
        return $string;
    }
    private function strippadding($string) {
        $slast = ord(substr($string, -1));
        $slastc = chr($slast);
        $pcheck = substr($string, -$slast);
        if (preg_match("/$slastc{" . $slast . "}/", $string)) {
            $string = substr($string, 0, strlen($string) - $slast);
            return $string;
        } else {
            return false;
        }
    }

    function hexToStr($hex)
    {
        $string='';
        for ($i=0; $i < strlen($hex)-1; $i+=2)
        {
            $string .= chr(hexdec($hex[$i].$hex[$i+1]));
        }
        return $string;
    }

    /**
     *url 安全的base64编码 sunlonglong
     */
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    /**
     *url 安全的base64解码 sunlonglong
     */
    function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}









