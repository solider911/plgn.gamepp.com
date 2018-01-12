<?php
/**
 *PHPer:liu
 *time:2017/12/29/029 11:50
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;

use app\common\Curl;
use app\common\common\Email;
use app\common\common\OAuthException;
use app\common\common\QQsdk;
use think\Controller;
use think\Cookie;
use think\Db;
use think\Request;
use think\Session;
use app\common\common\Oauth;
use app\common\common\SaeTClientV2;
use think\Url;
url::root('/index.php?s=');

class LoginSteam extends Controller {

    private $login_url_web = "http://plgn.gamepp.com/?s=/index/login/index";
    private $login_url_app = "http://plgn.gamepp.com/?s=/index/login/pc_login";

    private $steam_login_url = "http://steam.gamepp.com/steam.php";

	//登录页面
	public function index(){
		return $this->fetch('index');
	}

	//登录验证
    public function login(Request $request){
        //获取当前邮箱
//        echo "steam login coming..."."<br/>";
        $uemail = input('email');

        Header("Location: {$this->steam_login_url}");

//        $steam_login_info = file_get_contents($this->steam_login_url);

//        print_r($steam_login_info);

        return $uemail;
    }

    // steam登录成功后的回调地址

    public function login_callback(){

	    echo "steam_login_callback haha"."<br/>";

/*	    $steam_info = file_get_contents('php://input');

	    echo $steam_info;*/

    }



    //绑定成功页面
    public function  bd_ok(){
	    return $this->fetch();
    }

    //绑定失败页面
    public function  bd_no(){
        return $this->fetch();
    }
}