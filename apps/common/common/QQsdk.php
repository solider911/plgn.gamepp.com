<?php
namespace app\common\common;

class QQsdk
{
    private $app_id = '101456064';
    private $app_secret = '53e51ff07928168b03f6e1f34007858a';
    private $redirect = 'http://plgn.gamepp.com/?s=/index/login/qqCallback';

    function __construct()
    {

    }

    /**
     * [get_open_id 获取用户唯一ID，openid]
     * @param [string] $token [授权码]
     * @return [array] [成功返回client_id 和 openid ;失败返回error 和 error_msg]
     */
    function get_open_id($token)
    {
        $str = $this->curl_get_content('https://graph.qq.com/oauth2.0/me?access_token=' . $token);
        if (strpos($str, "callback") !== false) {
            $lpos = strpos($str, "(");
            $rpos = strrpos($str, ")");
            $str = substr($str, $lpos + 1, $rpos - $lpos - 1);
        }
        $user = json_decode($str, TRUE);
        return $user;
    }

    /**
     * [get_access_token 获取access_token]
     * @param [string] $code [登陆后返回的$_GET['code']]
     * @return [array] [expires_in 为有效时间 , access_token 为授权码 ; 失败返回 error , error_description ]
     */
    function get_access_token($code)
    {
        $token_url = 'https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&'
            . 'client_id=' . $this->app_id . '&redirect_uri=' . urlencode($this->redirect) . '&client_secret=' . $this->app_secret . '&code=' . $code;
        $token = array();
        parse_str($this->curl_get_content($token_url), $token);
        return $token;

    }

    /**
     * [get_user_info 获取用户信息]
     * @param [string] $token [授权码]
     * @param [string] $open_id [用户唯一ID]
     * @return [array] [ret：返回码，为0时成功。msg为错误信息,正确返回时为空。...params]
     */
    function get_user_info($token, $open_id)
    {
        $user_info_url = 'https://graph.qq.com/user/get_user_info?' . 'access_token=' . $token . '&oauth_consumer_key=' . $this->app_id . '&openid=' . $open_id . '&format=json';
        $info = json_decode($this->curl_get_content($user_info_url), TRUE);
        return $info;
    }

    private function curl_get_content($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_URL, $url);
        //设置超时时间为3s
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
}