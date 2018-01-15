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
use app\common\common\AES;
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

    private $login_url_web = "http://plgn.gamepp.com/?s=/index/login/index";    // 网页登录页面
    private $login_url_app = "http://plgn.gamepp.com/?s=/index/login/pc_login";         // app登录页面
    private $person_info_url = "http://plgn.gamepp.com/index.php?s=/index/personal/my_info";   // 个人中心首页

    private $steam_login_url = "http://steam.gamepp.com/steam.php";     // steam第三方登录页面
    private $steam_login_url_callback = "http://plgn.gamepp.com/index.php?s=/index/login_steam/login_callback/sd/...";

	//登录页面
	public function index(){
	    dump(Session::get('usename'));
	    return;
		return $this->fetch('index');
	}

	//登录验证
    public function login(Request $request){
        //获取当前邮箱
        $uemail = input('email');
        Session::set("u_email", $uemail);
        Header("Location: {$this->steam_login_url}");
    }

    // steam登录成功后的回调地址
    public function login_callback(){

        $u_email = Session::get("u_email");
        $steam_origin = input('sd');
        $steam_data = base64_decode($steam_origin);
        $steam_array = json_decode($steam_data, true);  // steam用户基本信息

        // 查询steam账号信息
        $steamInfo = Db::table('ys_login_steam')
            ->where('user_steamid','=',$steam_array['steamid'])
            ->find();

        if (empty($steamInfo)){
            $steamInfo['user_steamid']     = $steam_array['steamid'];   // steamid
            $steamInfo['user_personaname'] = $steam_array['uname'];     // steam角色名称
            $steamInfo['user_avatar']      = $steam_array['avatar'];    // 头像小
            $steamInfo['user_token']       = $this->get_token($steam_array['steamid']);
            $steamInfo['user_creat_tm']    = time();// 账号创建时间戳
            $steamInfo['user_login_tm']    = time();// 账号创建时间戳
            // 存入steam账号信息
            Db::table('ys_login_steam')->insert($steamInfo);
            $user_Id = Db::table('ys_login_steam')->getLastInsID();
            if (empty($user_Id))
                return "steam 绑定失败";

            // email绑定
            $this->bind_email($u_email, $user_Id);
        }
        else{

            $steamUpdate['user_login_tm'] = time();
            $steamUpdate['user_token'] = $this->get_token($steam_array['steamid']);

            Db::table('ys_login_steam')
                ->where('user_id','=',$steamInfo['user_id'])
                ->update($steamUpdate);

            $this->bind_email($u_email, $steamInfo['user_id']);
        }
    }


    /**
     * @param Request $request
     * @return \think\response\Json 取消steam绑定
     */
    public function bind_cancel(Request $request){
        if($request->isAjax()){
            $u_email = input('post.u_email');

            if (empty($u_email)){
                return json(['success'=>false,'error'=>'邮箱获取失败,刷新页面重试']);
            }

            $steam_bind_cancel = Db::table('ys_login_account')
                ->where('user_account','=',$u_email)
                ->setField('user_steam_id', '');

            if($steam_bind_cancel == true){
                return json(['success'=>true]);
            }else{
                return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
            }
        }
    }



    //绑定成功页面
    public function  bd_ok(){
	    return $this->fetch();
    }

    //绑定失败页面
    public function  bd_no(){
        return $this->fetch();
    }


//    /******************* 私有接口 **********************/


    /**
     * @param $email_account  // 邮箱账号
     * @param $user_id        // 第三方登录账号自增id
     */
    private function bind_email($email_account, $bind_id){

        $ctime = date("Y-m-d H:i:s");
        $sql_email_account = "insert into ys_login_account (user_account, user_create_time, user_last_login_time, user_steam_id) VALUES
                              ('{$email_account}', '{$ctime}', '{$ctime}', $bind_id) 
                              ON DUPLICATE KEY UPDATE user_last_login_time='{$ctime}', user_steam_id=$bind_id;";

        $affect_rows = Db::table('ys_login_steam')->execute($sql_email_account);


        return header("Location:{$this->person_info_url}");
    }

    private function get_token($account_id){
	    return hash("sha1",$account_id.time());
    }


}