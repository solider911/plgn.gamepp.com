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

class Login extends Controller {

    private $login_url_web = "http://plgn.gamepp.com/?s=/index/login/index";
    private $login_url_app = "http://plgn.gamepp.com/?s=/index/login/pc_login";

	//登录页面
	public function index(){
	    if(Session::get('username')){
            $code_url = "http://plgn.gamepp.com/index.php?s=/index/personal/my_info";
            return header("Location:".$code_url);
        }
	    if(Cookie::get('is_rem') !== '1'){
            Cookie::set('is_rem','0');
            Session::set('username',null);
            Session::set('password',null);

            $data = array(
                'username'=>Session::get('username'),
                'pwd'=>Session::get('password'),
                'rem'=>'0'
            );
        }else{
            $data = array(
                'username'=>Session::get('username'),
                'pwd'=>Session::get('password'),
                'rem'=>'1'
            );
        }
	    $this->assign('data',$data);
		return $this->fetch('index');
	}

	//登录验证
    public function login(Request $request){
        if($request->isAjax()){
            $username = input('post.username');
            $pwd = input('post.pwd');
            $keep_pwd = input('post.keep_pwd'); //0为没记住密码 1为记住密码
            $re_lo = input('post.re_lo'); //0为不自动登录 1为自动登录
            $pwd_len = input('post.pwd_len');

            //数据验证
            $form_data = [
                'user_account'=>$username,
                'user_pwd'=>$pwd
            ];

            //用户验证
            $rule_user = [
                'user_account' => 'require|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.email' => '邮箱格式不正确',
            ];

            //密码验证
            $rule_pwd = [
                'user_pwd' => 'require'
            ];
            $msg_pwd= [
                'user_pwd.require' => '密码不能为空',
            ];

            //进行验证
            $result_user = $this->validate($form_data,$rule_user,$msg_user);  //用户
            $result_pwd = $this->validate($form_data,$rule_pwd,$msg_pwd);  //密码


            //数据库验证 验证通过
            if($result_user === true && $result_pwd === true){
                //判断用户是否存在
                $user = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();

                if($user == null){
                    return json(['success'=>false,'error'=>'202']); //用户不存在
                }

                //判断用户是否被激活
                if($user['user_is_act'] != '1'){
                    return json(['success'=>false,'error'=>'203']); //用户未激活
                }
                //判断用户是否被冻结
                if($user['user_is_free'] != '1'){
                    return json(['success'=>false,'error'=>'204']); //用户被冻结
                }

                if($pwd_len<6 || $pwd_len>16){
                    return json(['success'=>false,'error'=>'304']);
                }


                //获取盐值
                $salt = $user['user_salt'];
                //密码盐值加密
                $pwd_sa = md5($pwd.$salt);
                //判断密码是否正确
                $check_pwd = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->where('user_pwd','=',$pwd_sa)
                    ->find();

                if($check_pwd == null){
                    return json(['success'=>false,'error'=>'205']); //密码错误
                }
                //记住密码处理
                if($keep_pwd == '1'){
                    Cookie::set('is_rem','1');  //是否记住密码 是
                    Session::set('username',$username); //记录邮箱名
                    Session::set('password',$pwd);   //记住密码
                }else{
                    Session::set('username',$username);
                    Cookie::set('is_rem','0'); //否
                }

                // 更新用户状态
                Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->setInc('user_login_num');

                Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->setField('user_last_login_time',date('Y-m-d H-i-s'));

                //pc登录
                $utype = input('utype');


                if($utype == '0'){

                    $user_info = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->setField('user_token',hash("sha1",$username.time().$salt));
                    $user_data = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->find();


                    //判断是否绑定steam
                    if($user_data['user_steam_id'] == null){
                        $bdsteam = '0';
                    }else{
                        $bdsteam = '1';
                    }

                    //获取steam头像
                     $img_data = $this->headerimg($user_data['user_account_id'],'user_account_id');

                    if($img_data == false){
                        $img_data = 'http://plgn.gamepp.com/public/deimg/tx_default.png';
                    }
                    return json([
                        'success'=>true,
                        'utype'=>$utype,
                        'uid'=>$username,
                        'token'=>$user_data['user_token'],
                        'nickname'=>$user_data['user_nickname'],
                        'imgurl'=>$img_data,
                        'isemail'=>'1',
                        'bdsteam'=> $bdsteam
                    ]);
                }

                //传入session 判断登陆
                Session::set('username',$username);
                return json(['success'=>true]);

            }else{
                //填写验证失败
                if($result_user !== true){
                    return json(['success'=>false,'error'=>'300','info'=>$result_user]);
                }
                if($result_pwd !== true){
                    return json(['success'=>false,'error'=>'302','info'=>$result_pwd]);
                }
            }
        }
    }

    //第三方登录
    //微博oauth2.0授权登录
    public function weibologin(){
	    //pc端登录类型
	    $utype = input('utype');
	    //获取当前邮箱
	    $uemail = input('uemail');
	    //个人中心绑定类型
        $bd_type = input('bd_type');

        //实例化微博oauth类 获取授权窗口
        $oAuth = new Oauth('2067469895','5b3bd631e64e4c051ee3d3d57bbd5dcd');

        //微博绑定
        if($bd_type == '0'){
            $code_url = $oAuth->getAuthorizeURL("http://plgn.gamepp.com/?s=index/login/weiboLoginCallback/bd_type/{$bd_type}/uemail/{$uemail}");
        }else{
            $code_url = $oAuth->getAuthorizeURL("http://plgn.gamepp.com/?s=index/login/weiboLoginCallback/utype/{$utype}");
        }
        return header("Location:".$code_url);
    }

    //微博回调
    public function weiboLoginCallback(Request $request){
        //定义空token 用于返回时报错
        $token = null;

        //实例化微博oAuth类
        $oAuth = new Oauth('2067469895','5b3bd631e64e4c051ee3d3d57bbd5dcd');
        //直接使用微博aouth dome代码
        if (isset($_REQUEST['code'])) {
            $keys = array();
            $keys['code'] = $_REQUEST['code'];
            $keys['redirect_uri'] = "http://plgn.gamepp.com/?s=index/login/weiboLoginCallback";
            try {
                $token = $oAuth->getAccessToken( 'code', $keys ) ;
            } catch (OAuthException $e) {
            }
        }

        //获取到assoc_token
        if ($token) {
            setcookie( 'weibojs_'.$oAuth->client_id, http_build_query($token) );
            //实例化SaeTClientV2类获取到用户信息 注意:该类在oauth类中下半部分 注意修改构造方法中实例化的oauth类
            $oAuthResult = new SaeTClientV2( '2067469895' , '5b3bd631e64e4c051ee3d3d57bbd5dcd', $token['access_token'] );
            //获取用户uid
            $uid_get = $oAuthResult->get_uid();
            //根据uid获取微博用户信息
            $wb_data = $oAuthResult->show_user_by_id($uid_get['uid']);

            //个人中心绑定 bd_type
            $bd_info = $request->param();

            //判断第三方是否登录过
            $wbUserInfo = Db::table('ys_login_wb')
                ->where('user_wb_openid','=',$wb_data['id'])
                ->find();

            //个人中心微博绑定
            if(isset($bd_info['bd_type']) && $bd_info['bd_type'] == '0'){
                //获取user_wb_id用户表是否绑定
                $bd_wb = Db::table('ys_login_account')
                    ->where('user_account','=',$bd_info['uemail'])
                    ->find();
                //个人中心没有绑定 第三方账号不存在
                if($bd_wb['user_wb_id'] == null && $wbUserInfo == false ){
                    //如果微博用户第一次登录 保存信息
                    $userInfo['user_wb_name']    = $wb_data['screen_name'];   //微博昵称
                    $userInfo['user_wb_image_url']    = $wb_data['profile_image_url'];   //微博头像
                    $userInfo['user_wb_openid']    = $wb_data['id'];   //openid
                    $userInfo['user_wb_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                    $userInfo['user_wb_last_time'] = date('Y-m-d H:i:s'); //最后登录时间
                    $userInfo['user_wb_bd_time'] = date('Y-m-d H:i:s'); //最后登录时间
                    //存入新数据
                    Db::table('ys_login_wb')->insert($userInfo);

                    //获取新插入的数据
                    $openid = Db::table('ys_login_wb')
                        ->where('user_wb_openid','=',$wb_data['id'])
                        ->find();

                    //用户表更新数据  绑定第三方账号
                    $bd_wb = Db::table('ys_login_account')
                        ->where('user_account','=',$bd_info['uemail'])
                        ->setField('user_wb_id',$openid['user_wb_id']);
                }else{
                    //微博账号已经存在 没有绑定
                    $bd_wb = Db::table('ys_login_account')
                        ->where('user_account','=',$bd_info['uemail'])
                        ->setField('user_wb_id',$wbUserInfo['user_wb_id']);

                    $bd_wb = Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setField('user_wb_bd_time',date('Y-m-d H:i:s'));
                }

                $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                return header("Location:".$url);

            }

            //获取utype 判断客户端登录
            $utype = input('utype');

            //第三方已经登录
            if ($wbUserInfo==true){
                //客户端用微博登录
                if ($utype == '1'){
                    //微博更新
                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setInc('user_wb_login_num');

                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setField('user_wb_last_time',date('Y-m-d H:i:s'));

                    //查看用户表信息
                    $user_acc = Db::table('ys_login_account')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->find();

                    //判断是否绑定steam
                    $isemail = '0';
                    $bdsteam = '0';
                    if($user_acc == true){
                        $isemail = '1';
                        if($user_acc['user_steam_id'] != null ){
                            $bdsteam = '1';
                        }
                    }

                    //产生token
                    $wb_token = hash("sha1",$wbUserInfo['user_wb_openid'].time());
                    $add_token = Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setField('user_wb_token',$wb_token);

                    $data['uid'] = $wb_data['id'];
                    $data['token'] = $wb_token;
                    $data['nickname'] =$wbUserInfo['user_wb_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $wbUserInfo['user_wb_image_url'];
                    $data['isemail'] = $isemail;
                    $data['bdsteam'] = $bdsteam;
                    return $this->pc_login_suc($data);
                }


                //获取用户 是否绑定
                $user_info = Db::table('ys_login_account')
                    ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                    ->find();


                //第三方已经绑定邮箱登录过
                if($user_info == true){
                    // 更新用户状态 账号更新
                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$wbUserInfo['user_wb_id'])
                        ->setInc('user_login_num');

                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$wbUserInfo['user_wb_id'])
                        ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                    //微博更新
                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setInc('user_wb_login_num');

                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$wbUserInfo['user_wb_id'])
                        ->setField('user_wb_last_time',date('Y-m-d H:i:s'));


                    Session::set('username',$user_info['user_account']);
                    Session::set('user_wb_id',$wbUserInfo['user_wb_id']);
                    Session::set('nickname',$wbUserInfo['user_wb_name']);
                    Session::set('header_img',$wbUserInfo['user_wb_image_url']);

                    $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                }else{
                    Session::set('wbcode',$wbUserInfo['user_wb_id']);
                    //第一次没有邮箱 绑定邮箱
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email1/wbcode/{$wbUserInfo['user_wb_id']}";
                }
                return Header("Location: $url");
            }else{

                //如果微博用户第一次登录 保存信息
                $userInfo['user_wb_name']    = $wb_data['screen_name'];   //微博昵称
                $userInfo['user_wb_image_url']    = $wb_data['profile_image_url'];   //微博头像
                $userInfo['user_wb_openid']    = $wb_data['id'];   //openid
                $userInfo['user_wb_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                $userInfo['user_wb_last_time'] = date('Y-m-d H:i:s'); //最后登录时间

                //客户端登录
                if($utype == '1'){
                    //存入新数据
                    Db::table('ys_login_wb')->insert($userInfo);

                    //用户数据
                    $user_info = Db::table('ys_login_wb')
                        ->where('user_wb_openid','=',$userInfo['user_wb_openid'])
                        ->find();

                    //产生token
                    $wb_token = hash("sha1",$userInfo['user_wb_openid'].time());

                    //保存token
                    $add_token = Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$user_info['user_wb_id'])
                        ->setField('user_wb_token',$wb_token);

                    //查看用户表信息
                    $user_acc = Db::table('ys_login_account')
                        ->where('user_wb_id','=',$user_info['user_wb_id'])
                        ->find();

                    //判断是否绑定steam
                    $isemail = '0';
                    $bdsteam = '0';
                    if($user_acc == true){
                        $isemail = '1';
                        if($user_acc['user_steam_id'] != null ){
                            $bdsteam = '1';
                        }
                    }

                    $data['uid'] = $wb_data['id'];
                    $data['token'] = $wb_token;
                    $data['nickname'] =$user_info['user_wb_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $user_info['user_wb_image_url'];
                    $data['isemail'] = '0';
                    $data['bdsteam'] = '0';
                    return $this->pc_login_suc($data);
                }

                //网页授权登录时保存
                $data = Db::table('ys_login_wb')->insert($userInfo);
                //获取新数据
                $user_info = Db::table('ys_login_wb')
                    ->where('user_wb_openid','=',$userInfo['user_wb_openid'])
                    ->find();
                    //第一次没有邮箱 绑定邮箱
                    Session::set('wbcode',$user_info['user_wb_id']);
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email1/wbcode/{$user_info['user_wb_id']}";
                    return Header("Location: $url");
            }
        }else{
            return header("Location:{$this->login_url_web}");
        }
    }

    //微博发送验证邮箱
    public function bd_email1(Request $request){
        if($request->isAjax()){
            $username = input('post.username');
            $check_rem = input('post.check_rem');
            //数据验证
            $form_data = [
                'user_account'=>$username,
            ];
            //用户密码分开验证方便前台返回
            //用户验证
            $rule_user = [
                'user_account' => 'require|max:64|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多64个字符',
                'user_account.min' => '邮箱最少4个字符',
                'user_account.email' => '邮箱格式不正确',
            ];

            //进行验证
            $result_user = $this->validate($form_data,$rule_user,$msg_user);  //用户
            //数据库验证 验证通过
            if($result_user === true){
                //判断用户是否勾选
                if($check_rem != '1'){
                    return json(['success'=>false,'error'=>'208']);
                }
                //判断邮箱是否绑定
                $user_account = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();
                if($user_account['user_wb_id'] != null){
                    return json(['success'=>false,'error'=>'206']);
                }

                //邮箱激活随机码
                $user_active_code = hash('sha1',$username.time());
                //保存入库激活码
                $user_act['user_wb_act_code'] = $user_active_code;
                $user_act['user_wb_act_code_time'] = time()+7200;
                //获取wb_user_id
                $user_wb_id =Session::get('wbcode');
                $act_email = Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$user_wb_id)
                    ->setField($user_act);
                //调用邮箱类
                if($act_email == true){
                    //随机密码
                    $pwd = mt_rand(10000000,99999999);
                    $pwd1 = md5($pwd);
                    $email = new Email();
                    //判断邮箱是否存在  存在就不发送密码密码
                    $account = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->find();

                    if($account['user_account'] != null){
                        $wbrand = mt_rand(1,10000);
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$user_wb_id}/uCode/{$user_active_code}/wbrand/{$wbrand}/user_email/{$username}/act_bd_type/1";
                        $email->mail_certification($username,$confirm_url);
                    }else{
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$user_wb_id}/uCode/{$user_active_code}/wbrand/{$pwd1}/user_email/{$username}/act_bd_type/1";
                        $email->mail_certification_bind($username,$confirm_url,$pwd);
                    }

                    if($email == true) {
                        return json(['success' => true, 'user_wb_id' => $user_wb_id, 'uCode' => $user_active_code, 'username' => $username]);
                    }
                }
            }else{
                //验证不通过
                return json(['success'=>false,'error'=>'300','info'=>$result_user]);
            }
        }
        return $this->fetch();
    }

    //微博邮箱重新发送
    public function cx_email(Request $request){
        //核实激活码 重新发送
        //获取邮件激活信息
        $data = $request->param();
        $username = $data['username'];
        $user_active_code =$data['uCode'];
        $user_wb_id =$data['user_wb_id'];
        if($request->isAjax()){

            $cx_code = Db::table('ys_login_wb')
                ->where('user_wb_id','=',$user_wb_id)
                ->where('user_wb_act_code','=',$user_active_code)
                ->find();
            if($cx_code != true){
                return json(['success'=>false]);
            }

            //邮箱激活随机码
            $user_active_code = hash("sha1",$username.time());

            //保存入库激活码
            $user_act['user_wb_act_code'] = $user_active_code;
            $user_act['user_wb_act_code_time'] = time()+7200;

            $act_email = Db::table('ys_login_wb')
                ->where('user_wb_id','=',$user_wb_id)
                ->setField($user_act);

            //随机密码
            $pwd = mt_rand(10000000,99999999);
            $pwd1 = md5($pwd);

            $email = new Email();
            $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$user_wb_id}/uCode/{$user_active_code}/wbrand/{$pwd1}/user_email/{$username}/act_bd_type/1";
            $email->mail_certification_bind($username,$confirm_url,$pwd);

            if($email == true){
                return json(['success'=>true,'user_wb_id'=>$user_wb_id,'uCode'=>$user_active_code,'wbrand'=>$pwd]);
            }
        }
    }

    //qq微信授权页面
    public function qqlogin(){
        //微信
        $arr['access_token'] = null;
        $arr['openid'] = null;
        $app_id = '101457184';
        $redirect = 'http://plgn.gamepp.com/?s=/index/login/qqCallback';
        //$redirect 为回调地址  $app_id 应用编号

        //获取客户端登录方式
        $utype = input('utype');
        //获取当前邮箱
        $uemail = input('uemail');
        //个人中心绑定类型
        $bd_type = input('bd_type');

        Session::set('bd_type',$bd_type);
        Session::set('uemail',$uemail);
        Session::set('utype',$utype);

        $url = 'https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id='.$app_id.'&redirect_uri='.$redirect;
        header('Location:'.$url);
    }

    //微信授权登录
    public function wxlogin(){
        $AppID = 'wx34b8df32b5856692';
        $AppSecret = '1dba5b7eab656a1c23448cc067519d90';
        $callback  =  'http://plgn.gamepp.com'; //回调地址

        //获取客户端登录方式
        $utype = input('utype');
        //获取当前邮箱
        $uemail = input('uemail');
        //个人中心绑定类型
        $bd_type = input('bd_type');

        Session::set('bd_type',$bd_type);
        Session::set('uemail',$uemail);
        Session::set('utype',$utype);

        //-------生成唯一随机串防CSRF攻击
        $state  = md5(uniqid(rand(), TRUE));
        Session::set('wx_state',$state); //存到SESSION
        $callback = urlencode($callback);
        $wxurl = "https://open.weixin.qq.com/connect/qrconnect?appid=".$AppID."&redirect_uri={$callback}&response_type=code&scope=snsapi_login&state={$state}#wechat_redirect";
        header("Location: $wxurl");
    }

    //qq微信回调地址  公用一个地址
    public function qqCallback(){
	    //客户端跳到网页防止报错
	    if(!isset($_GET['code'])){
            return header("Location:{$this->login_url_app}");
        }
        //获取邮箱
        $uemail = Session::get('uemail');
        //获取客户端微信登录utype
        $utype = Session::get('utype');
        //微信授权验证
        if(!isset($_GET['state'])){
            $_GET['state'] = '111';
        }

        if($_GET['state']==Session::get('wx_state')){
            $AppID = 'wx34b8df32b5856692';
            $AppSecret = '1dba5b7eab656a1c23448cc067519d90';
            $url='https://api.weixin.qq.com/sns/oauth2/access_token?appid='.$AppID.'&secret='.$AppSecret.'&code='.$_GET['code'].'&grant_type=authorization_code';
            $curl = new Curl();
            $arr = $curl->curl($url);

            //网页第三方登录取消
            if(!isset($arr['access_token']) || !isset($arr['openid'])){
                return header("Location:{$this->login_url_web}");
            }

            //得到 access_token 与 openid
            $url='https://api.weixin.qq.com/sns/userinfo?access_token='.$arr['access_token'].'&openid='.$arr['openid'].'&lang=zh_CN';
            $wx_data = $curl->curl($url);

            //判断第三方是否登录过
            $wxUserInfo = Db::table('ys_login_wx')
                ->where('user_wx_openid','=',$wx_data['unionid'])
                ->find();

            //微信个人中心绑定
            if(Session::get('bd_type') =='1' ){
                //获取user_wb_id用户表是否绑定
                $bd_wx = Db::table('ys_login_account')
                    ->where('user_account','=',$uemail)
                    ->find();
                if($bd_wx['user_wx_id'] == null  && $wxUserInfo == null ){
                    //如果微博用户第一次登录 保存信息
                    $userInfo['user_wx_name']    = $wx_data['nickname'];   //微博昵称
                    $userInfo['user_wx_image_url']    = $wx_data['headimgurl'];    //微博头像
                    $userInfo['user_wx_openid']    = $wx_data['unionid'];   //openid
                    $userInfo['user_wx_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                    $userInfo['user_wx_last_time'] = date('Y-m-d H:i:s'); //最后登录时间
                    $userInfo['user_wx_bd_time'] = date('Y-m-d H:i:s'); //最后登录时间

                    //存入新数据
                    Db::table('ys_login_wx')->insert($userInfo);

                    $openid = Db::table('ys_login_wx')
                        ->where('user_wx_openid','=',$wx_data['unionid'])
                        ->find();

                    $bd_wx = Db::table('ys_login_account')
                        ->where('user_account','=',$uemail)
                        ->setField('user_wx_id',$openid['user_wx_id']);
                }else{
                    $bd_wx = Db::table('ys_login_account')
                        ->where('user_account','=',$uemail)
                        ->setField('user_wx_id',$wxUserInfo['user_wx_id']);

                    $bd_wb = Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                        ->setField('user_wx_bd_time',date('Y-m-d H:i:s'));
                }

                $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                return header("Location:".$url);
            }

            //数据库有信息 已经登录
            if($wxUserInfo == true){
                //客户端微信登录
                if ($utype == '3'){
                    $wx_token = hash("sha1",$wxUserInfo['user_wx_openid'].time());
                    //保存token
                   Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                        ->setField('user_wx_token',$wx_token);

                    //查看用户表信息
                    $user_acc = Db::table('ys_login_account')
                        ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                        ->find();
                    //判断是否绑定steam
                    $isemail = '0';
                    $bdsteam = '0';
                    if($user_acc == true){
                        $isemail = '1';
                        if($user_acc['user_steam_id'] != null ){
                            $bdsteam = '1';
                        }
                    }
                    //返回客户端数据
                    $data['uid'] = $wx_data['unionid'];
                    $data['token'] = $wx_token;
                    $data['nickname'] =$wxUserInfo['user_wx_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $wx_data['headimgurl'];
                    $data['isemail'] = $isemail;
                    $data['bdsteam'] = $bdsteam;
                    return $this->pc_login_suc($data);
                }


                // 获取数据 网页登录查看是否绑定邮箱
                $user_info = Db::table('ys_login_account')
                    ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                    ->find();

                //第三方微信已经绑定
                if($user_info == true){
                    // 更新用户状态 账号更新
                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$wxUserInfo['user_wx_id'])
                        ->setInc('user_login_num');

                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$wxUserInfo['user_wx_id'])
                        ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                    //微博更新
                    Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                        ->setInc('user_wx_login_num');

                    Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$wxUserInfo['user_wx_id'])
                        ->setField('user_wx_last_time',date('Y-m-d H:i:s'));


                    Session::set('username',$user_info['user_account']);
                    Session::set('user_wx_id',$wxUserInfo['user_wx_id']);
                    Session::set('nickname',$wxUserInfo['user_wx_name']);
                    Session::set('header_img',$wxUserInfo['user_wx_image_url']);

                    $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                    return header("Location:".$url);

                }else{
                    //微信没绑定
                    Session::set('wxcode',$wxUserInfo['user_wx_id']);
                    //第一次没有邮箱 绑定邮箱
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email2/wxcode/{$wxUserInfo['user_wx_id']}";
                    return Header("Location: $url");
                }

            }else{
                //如果是新用户 保存信息
                $userInfo['user_wx_name']    = $wx_data['nickname'];   //微博昵称
                $userInfo['user_wx_image_url']    = $wx_data['headimgurl'];   //微博头像
                $userInfo['user_wx_openid']    = $wx_data['unionid'];   //openid
                $userInfo['user_wx_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                $userInfo['user_wx_last_time'] = date('Y-m-d H:i:s'); //最后登录时间

                //客户端存入
                if($utype == '3'){
                    //存入新数据
                    Db::table('ys_login_wx')->insert($userInfo);

                    //用户数据
                    $user_info = Db::table('ys_login_wx')
                        ->where('user_wx_openid','=',$userInfo['user_wx_openid'])
                        ->find();
                    //token判断
                    $add_token = Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$user_info['user_wx_id'])
                        ->setField('user_wx_token',hash("sha1",$userInfo['user_wx_openid'].time()));
                    //获取token
                    $user_data = Db::table('ys_login_wx')
                        ->where('user_wx_id','=',$user_info['user_wx_id'])
                        ->find();
                    //返回数据
                    $data['uid'] =$wx_data['unionid'];
                    $data['token'] = $user_data['user_wx_token'];
                    $data['nickname'] =$user_info['user_wx_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $user_info['user_wx_image_url'];
                    $data['isemail'] = '0';
                    $data['bdsteam'] = '0';
                    return $this->pc_login_suc($data);
                }
                //存入
                $data = Db::table('ys_login_wx')->insert($userInfo);
                //存入成功 查看id
                $user_wx_id = Db::table('ys_login_wx')
                    ->where('user_wx_openid','=',$userInfo['user_wx_openid'])
                    ->find();
                Session::set('wxcode',$user_wx_id['user_wx_id']);
                //第一次登录肯定要绑定邮箱 wbcode 第三方id 用户关联用户表
                $url = "http://plgn.gamepp.com/?s=index/login/bd_email2/wxcode/{$user_wx_id['user_wx_id']}";
                return Header("Location: $url");
            }
        }

        //qq授权验证
        if(isset($_GET['code'])) {
            $qq_sdk = new QQsdk();
            $token = $qq_sdk->get_access_token($_GET['code']);
            $openid =  $qq_sdk->get_open_id($token['access_token']);
            $qq_data =  $qq_sdk->get_user_info($token['access_token'],$openid['openid']);
            //判断第三方是否登录过   $openid['openid']为qq唯一辨识id
            $qqUserInfo = Db::table('ys_login_qq')
                ->where('user_qq_openid','=',$openid['openid'])
                ->find();

            //qq个人中心绑定
            if(Session::get('bd_type') =='2' ){
                //获取user_wb_id用户表是否绑定
                $bd_wx = Db::table('ys_login_account')
                    ->where('user_account','=',$uemail)
                    ->find();
                if($bd_wx['user_qq_id'] == null && $qqUserInfo == null ){
                    //如果微博用户第一次登录 保存信息
                    $userInfo['user_qq_name']    = $qq_data['nickname'];   //微博昵称
                    $userInfo['user_qq_image_url']    = $qq_data['figureurl_1'];    //微博头像
                    $userInfo['user_qq_openid']    = $openid['openid'];   //openid
                    $userInfo['user_qq_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                    $userInfo['user_qq_last_time'] = date('Y-m-d H:i:s'); //最后登录时间
                    $userInfo['user_qq_bd_time'] = date('Y-m-d H:i:s'); //最后登录时间

                    //存入新数据
                    Db::table('ys_login_qq')->insert($userInfo);

                    $openid = Db::table('ys_login_qq')
                        ->where('user_qq_openid','=',$openid['openid'])
                        ->find();

                    $bd_wx = Db::table('ys_login_account')
                        ->where('user_account','=',$uemail)
                        ->setField('user_qq_id',$openid['user_qq_id']);
                }else{
                    $bd_wx = Db::table('ys_login_account')
                        ->where('user_account','=',$uemail)
                        ->setField('user_qq_id',$qqUserInfo['user_qq_id']);

                    $bd_wb = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$qqUserInfo['user_qq_id'])
                        ->setField('user_qq_bd_time',date('Y-m-d H:i:s'));
                }
                $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                return header("Location:".$url);
            }

            //qq数据库有信息 已经登录
            if($qqUserInfo == true){
                //客户端微信登录

                if ($utype == '2'){
                    //用户数据
                    $user_info = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$qqUserInfo['user_qq_id'])
                        ->find();
                    //token
                    $add_token = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$user_info['user_qq_id'])
                        ->setField('user_qq_token',hash("sha1",$user_info['user_qq_openid'].time()));
                    //获取token
                    $user_data = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$user_info['user_qq_id'])
                        ->find();

                    //查看用户表信息
                    $user_acc = Db::table('ys_login_account')
                        ->where('user_qq_id','=',$user_info['user_qq_id'])
                        ->find();
                    //判断是否绑定steam
                    $isemail = '0';
                    $bdsteam = '0';
                    if($user_acc == true){
                        $isemail = '1';
                        if($user_acc['user_steam_id'] != null ){
                            $bdsteam = '1';
                        }
                    }
                    //返回客户端数据
                    $data['uid'] = $openid['openid'];
                    $data['token'] = $user_data['user_qq_token'];
                    $data['nickname'] =$user_info['user_qq_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $qq_data['figureurl_1'];
                    $data['isemail'] = $isemail;
                    $data['bdsteam'] = $bdsteam;
                    return $this->pc_login_suc($data);
                }

                // 获取数据 网页登录查看是否绑定邮箱
                $user_info = Db::table('ys_login_account')
                    ->where('user_qq_id','=',$qqUserInfo['user_qq_id'])
                    ->find();

                //qq绑定
                if($user_info == true){
                    // 更新用户状态 账号更新
                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$qqUserInfo['user_qq_id'])
                        ->setInc('user_login_num');

                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$qqUserInfo['user_qq_id'])
                        ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                    //微博更新
                    Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$qqUserInfo['user_qq_id'])
                        ->setInc('user_qq_login_num');

                    Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$qqUserInfo['user_qq_id'])
                        ->setField('user_qq_last_time',date('Y-m-d H:i:s'));


                    Session::set('username',$user_info['user_account']);
                    Session::set('user_qq_id',$qqUserInfo['user_qq_id']);
                    Session::set('nickname',$qqUserInfo['user_qq_name']);
                    Session::set('header_img',$qqUserInfo['user_qq_image_url']);

                    $url = "http://plgn.gamepp.com/?s=/index/personal/my_info";
                    return header("Location:".$url);

                }else{
                    //微信没绑定
                    Session::set('qqcode',$qqUserInfo['user_qq_id']);
                    //第一次没有邮箱 绑定邮箱
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email3/qqcode/{$qqUserInfo['user_qq_id']}";
                    return Header("Location: $url");
                }

            }else{
                //如果是新用户 保存信息
                $userInfo['user_qq_name']    = $qq_data['nickname'];   //微博昵称
                $userInfo['user_qq_image_url']    = $qq_data['figureurl_1'];   //微博头像
                $userInfo['user_qq_openid']    = $openid['openid'];   //openid
                $userInfo['user_qq_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                $userInfo['user_qq_last_time'] = date('Y-m-d H:i:s'); //最后登录时间

                //客户端存入
                if($utype == '2'){
                    //存入新数据
                    Db::table('ys_login_qq')->insert($userInfo);

                    //用户数据
                    $user_info = Db::table('ys_login_qq')
                        ->where('user_qq_openid','=',$userInfo['user_qq_openid'])
                        ->find();
                    //token判断
                    $add_token = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$user_info['user_qq_id'])
                        ->setField('user_qq_token',hash("sha1",$userInfo['user_qq_openid'].time()));
                    //获取token
                    $user_data = Db::table('ys_login_qq')
                        ->where('user_qq_id','=',$user_info['user_qq_id'])
                        ->find();
                    //返回数据
                    $data['uid'] =$openid['openid'];
                    $data['token'] = $user_data['user_qq_token'];
                    $data['nickname'] =$user_info['user_qq_name'];
                    $data['utype'] = $utype;
                    $data['imgurl'] = $user_info['user_qq_image_url'];
                    $data['isemail'] = '0';
                    $data['bdsteam'] = '0';
                    return $this->pc_login_suc($data);
                }
                //存入
                $data = Db::table('ys_login_qq')->insert($userInfo);
                //存入成功 查看id
                $user_qq_id = Db::table('ys_login_qq')
                    ->where('user_qq_openid','=',$userInfo['user_qq_openid'])
                    ->find();
                Session::set('qqcode',$user_qq_id['user_qq_id']);
                //第一次登录肯定要绑定邮箱 wbcode 第三方id 用户关联用户表
                $url = "http://plgn.gamepp.com/?s=index/login/bd_email3/qqcode/{$user_qq_id['user_qq_id']}";
                return Header("Location: $url");
            }
        }
    }

    //微信发送验证邮箱
    public function bd_email2(Request $request){
        if($request->isAjax()){
            $username = input('post.username');
            $check_rem = input('post.check_rem');

            //数据验证
            $form_data = [
                'user_account'=>$username,
            ];
            //用户密码分开验证方便前台返回
            //用户验证
            $rule_user = [
                'user_account' => 'require|max:64|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多64个字符',
                'user_account.min' => '邮箱最少4个字符',
                'user_account.email' => '邮箱格式不正确',
            ];

            //进行验证
            $result_user = $this->validate($form_data,$rule_user,$msg_user);  //用户
            //数据库验证 验证通过
            if($result_user === true){
                //判断用户是否勾选
                if($check_rem != '1'){
                    return json(['success'=>false,'error'=>'208']);
                }

                ///获取数据
                $user_account = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();

                //判断邮箱是否绑定
                if($user_account['user_wx_id'] != null){
                    return json(['success'=>false,'error'=>'206']);
                }

                //邮箱激活随机码
                $user_active_code = hash('sha1',$username.time());
                //保存入库激活码
                $user_act['user_wx_act_code'] = $user_active_code;
                $user_act['user_wx_act_code_time'] = time()+7200;


                //获取wb_user_id
                $user_wx_id = Session::get('wxcode');
                $act_email = Db::table('ys_login_wx')
                    ->where('user_wx_id','=',$user_wx_id)
                    ->setField($user_act);

                //调用邮箱类
                if($act_email == true){
                    //随机密码
                    $pwd = mt_rand(10000000,99999999);
                    $pwd1 = md5($pwd);
                    $email = new Email();

                    //判断邮箱是否存在  存在就不发送密码
                    $account = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->find();

                    if($account == true){
                        $wxrand = mt_rand(1,10000);
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wxcode/{$user_wx_id}/uCode/{$user_active_code}/wxrand/{$wxrand}/user_email/{$username}/act_bd_type/2";
                        $email->mail_certification($username,$confirm_url);
                    }else{
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wxcode/{$user_wx_id}/uCode/{$user_active_code}/wxrand/{$pwd1}/user_email/{$username}/act_bd_type/2";
                        $email->mail_certification_bind($username,$confirm_url,$pwd);
                    }

                    if($email == true) {
                        return json(['success' =>true,'user_wx_id'=>$user_wx_id,'uCode'=>$user_active_code,'username'=>$username]);
                    }
                }

                return json(['success'=>true]);
            }
        }
        return $this->fetch();
    }

    //微信邮箱重新发送
    public function cx_email2(Request $request){
        //核实激活码 重新发送
        //获取邮件激活信息
        $data = $request->param();

        $username = $data['username'];
        $user_active_code =$data['uCode'];
        $user_wx_id =$data['user_wx_id'];
        if($request->isAjax()){
            $cx_code = Db::table('ys_login_wx')
                ->where('user_wx_id','=',$user_wx_id)
                ->where('user_wx_act_code','=',$user_active_code)
                ->find();
            if($cx_code != true){
                return json(['success'=>false]);
            }

            //邮箱激活随机码
            $user_active_code = hash("sha1",$username.time());

            //保存入库激活码
            $user_act['user_wx_act_code'] = $user_active_code;
            $user_act['user_wx_act_code_time'] = time()+7200;

            $act_email = Db::table('ys_login_wx')
                ->where('user_wx_id','=',$user_wx_id)
                ->setField($user_act);

            //随机密码
            $pwd = mt_rand(10000000,99999999);
            $pwd1 = md5($pwd);

            $email = new Email();
            $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wxcode/{$user_wx_id}/uCode/{$user_active_code}/wxrand/{$pwd1}/user_email/{$username}/act_bd_type/2";
            $email->mail_certification_bind($username,$confirm_url,$pwd);

            if($email == true){
                return json(['success'=>true,'user_wx_id'=>$user_wx_id,'uCode'=>$user_active_code,'wxrand'=>$pwd]);
            }
        }
    }

    //qq发送验证邮箱
    public function bd_email3(Request $request){
        if($request->isAjax()){
            $username = input('post.username');
            $check_rem = input('post.check_rem');

            //数据验证
            $form_data = [
                'user_account'=>$username,
            ];
            //用户密码分开验证方便前台返回
            //用户验证
            $rule_user = [
                'user_account' => 'require|max:64|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多64个字符',
                'user_account.min' => '邮箱最少4个字符',
                'user_account.email' => '邮箱格式不正确',
            ];

            //进行验证
            $result_user = $this->validate($form_data,$rule_user,$msg_user);  //用户
            //数据库验证 验证通过
            if($result_user === true){
                //判断用户是否勾选
                if($check_rem != '1'){
                    return json(['success'=>false,'error'=>'208']);
                }

                ///获取数据
                $user_account = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();

                //判断邮箱是否绑定
                if($user_account['user_qq_id'] != null){
                    return json(['success'=>false,'error'=>'206']);
                }

                //邮箱激活随机码
                $user_active_code = hash('sha1',$username.time());
                //保存入库激活码
                $user_act['user_qq_act_code'] = $user_active_code;
                $user_act['user_qq_act_code_time'] = time()+7200;


                //获取wb_user_id
                $user_qq_id = Session::get('qqcode');
                $act_email = Db::table('ys_login_qq')
                    ->where('user_qq_id','=',$user_qq_id)
                    ->setField($user_act);
                //调用邮箱类
                if($act_email == true){
                    //随机密码
                    $pwd = mt_rand(10000000,99999999);
                    $pwd1 = md5($pwd);
                    $email = new Email();

                    //判断邮箱是否存在  存在就不发送密码
                    $account = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->find();

                    if($account['user_account'] != null && $account['user_qq_id'] == null){
                        $qqrand = mt_rand(1,10000);
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/qqcode/{$user_qq_id}/uCode/{$user_active_code}/qqrand/{$qqrand}/user_email/{$username}/act_bd_type/3";
                        $email->mail_certification($username,$confirm_url);
                    }else{
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/qqcode/{$user_qq_id}/uCode/{$user_active_code}/qqrand/{$pwd1}/user_email/{$username}/act_bd_type/3";
                        $email->mail_certification_bind($username,$confirm_url,$pwd);
                    }

                    if($email == true) {
                        return json(['success' =>true,'user_qq_id'=>$user_qq_id,'uCode'=>$user_active_code,'username'=>$username]);
                    }
                }

                return json(['success'=>true]);
            }
        }
        return $this->fetch();
    }

    //qq邮箱重新发送
    public function cx_email3(Request $request){
        //核实激活码 重新发送
        //获取邮件激活信息
        $data = $request->param();

        $username = $data['username'];
        $user_active_code =$data['uCode'];
        $user_qq_id =$data['user_qq_id'];
        if($request->isAjax()){
            $cx_code = Db::table('ys_login_qq')
                ->where('user_qq_id','=',$user_qq_id)
                ->where('user_qq_act_code','=',$user_active_code)
                ->find();
            if($cx_code != true){
                return json(['success'=>false]);
            }

            //邮箱激活随机码
            $user_active_code = hash("sha1",$username.time());

            //保存入库激活码
            $user_act['user_qq_act_code'] = $user_active_code;
            $user_act['user_qq_act_code_time'] = time()+7200;

            $act_email = Db::table('ys_login_qq')
                ->where('user_qq_id','=',$user_qq_id)
                ->setField($user_act);

            //随机密码
            $pwd = mt_rand(10000000,99999999);
            $pwd1 = md5($pwd);

            $email = new Email();
            $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/qqcode/{$user_qq_id}/uCode/{$user_active_code}/qqrand/{$pwd1}/user_email/{$username}/act_bd_type/3";
            $email->mail_certification_bind($username,$confirm_url,$pwd);

            if($email == true){
                return json(['success'=>true,'user_qq_id'=>$user_qq_id,'uCode'=>$user_active_code,'qqrand'=>$pwd]);
            }
        }
    }

    //微博,微信,qq第三方邮箱绑定激活
    public function act_code(Request $request){
        //获取参数
        $info = $request->param();

        //产生用户公共信息
        //产生盐值
        $salt  = substr(time(),-6);
        //随机昵称
        $rand_nickname  = "plgn_".mt_rand(10000,99999).substr(time(),-4);
        $data['user_nickname'] = $rand_nickname;
        $data['user_account'] = $info['user_email'];
        $data['user_salt'] =$salt;
        $data['user_create_time'] = date('Y-m-d H:i:s');
        $data['user_is_act'] = '1';

        //act_bd_type:1 微博 绑定未注册账号
        if($info['act_bd_type'] == '1'){
            //激活码验证
            $act_code= Db::table('ys_login_wb')
                ->where('user_wb_id','=',$info['wbcode'])
                ->where('user_wb_act_code','=',$info['uCode'])
                ->find();
            if($act_code == null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //激活时间是否过期
            if(time() > $act_code['user_wb_act_code_time']){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //微博关联id
            $data['user_wb_id'] = $info['wbcode'];
            //产生密码
            $data['user_pwd'] = md5($info['wbrand'].$salt);

            //判断邮箱是否存在
            $act_bd = Db::table('ys_login_account')
                ->where('user_account','=',$data['user_account'])
                ->find();
            if($act_bd['user_wb_id'] != null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            if($act_bd['user_account'] != null){
                $act_jh = Db::table('ys_login_account')
                    ->where('user_account','=',$data['user_account'])
                    ->setField('user_wb_id',$data['user_wb_id']);
            }else{
                //没有注册过的邮箱
                $act_jh =Db::table('ys_login_account')->insert($data);
            }

            if($act_jh == true){
                // 更新用户状态 账号更新
                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_wb_id'])
                    ->setInc('user_login_num');

                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_wb_id'])
                    ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                //微博更新
                Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$data['user_wb_id'])
                    ->setInc('user_wb_login_num');

                Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$data['user_wb_id'])
                    ->setField('user_wb_last_time',date('Y-m-d H:i:s'));

                $wb_data = Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$data['user_wb_id'])
                    ->find();

                //用户绑定 将用户邮箱存入session
                Session::set('nickname',$wb_data['user_wb_name']);
                Session::set('username',$data['user_account']);
                Session::set('user_wb_id',$data['user_wb_id']);
                Session::set('header_img',$wb_data['user_wb_image_url']);

                $url = "http://plgn.gamepp.com/?s=/index/login/bd_ok";
                return header("Location:".$url);
            }
        }

        //act_bd__type:2 微信 绑定未注册账号
        if($info['act_bd_type'] == '2'){
            //激活码验证
            $act_code= Db::table('ys_login_wx')
                ->where('user_wx_id','=',$info['wxcode'])
                ->where('user_wx_act_code','=',$info['uCode'])
                ->find();

            if($act_code == null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //激活时间是否过期
            if(time() > $act_code['user_wx_act_code_time']){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //获取id关联id
            $data['user_wx_id'] = $info['wxcode'];
            //产生密码
            $data['user_pwd'] = md5($info['wxrand'].$salt);

            //获取密码长度,判断邮箱是否存在
            $act_bd = Db::table('ys_login_account')
                ->where('user_account','=',$data['user_account'])
                ->find();
            if($act_bd['user_wx_id'] != null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            if($act_bd['user_account'] != null){
                $act_jh = Db::table('ys_login_account')
                    ->where('user_account','=',$data['user_account'])
                    ->setField('user_wx_id',$data['user_wx_id']);
            }else{
                //没有注册过的邮箱
                $act_jh =Db::table('ys_login_account')->insert($data);

            }
            if($act_jh == true){
                // 更新用户状态 账号更新
                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_wx_id'])
                    ->setInc('user_login_num');

                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_wx_id'])
                    ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                //微博更新
                Db::table('ys_login_wx')
                    ->where('user_wx_id','=',$data['user_wx_id'])
                    ->setInc('user_wx_login_num');

                Db::table('ys_login_wx')
                    ->where('user_wx_id','=',$data['user_wx_id'])
                    ->setField('user_wx_last_time',date('Y-m-d H:i:s'));


                $wx_data = Db::table('ys_login_wx')
                    ->where('user_wx_id','=',$data['user_wx_id'])
                    ->find();


                //用户绑定 将用户邮箱存入session
                Session::set('nickname',$wx_data['user_wx_name']);
                Session::set('username',$data['user_account']);
                Session::set('user_wx_id',$data['user_wx_id']);
                Session::set('header_img',$wx_data['user_wx_image_url']);

                $url = "http://plgn.gamepp.com/?s=/index/login/bd_ok";
                return header("Location:".$url);
            }
        }

        //act_bd__type:2 qq 绑定未注册账号
        if($info['act_bd_type'] == '3'){
            //激活码验证
            $act_code= Db::table('ys_login_qq')
                ->where('user_qq_id','=',$info['qqcode'])
                ->where('user_qq_act_code','=',$info['uCode'])
                ->find();

            if($act_code == null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //激活时间是否过期
            if(time() > $act_code['user_qq_act_code_time']){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //获取id关联id
            $data['user_qq_id'] = $info['qqcode'];
            //产生密码
            $data['user_pwd'] = md5($info['qqrand'].$salt);

            //判断邮箱是否存在
            $act_bd = Db::table('ys_login_account')
                ->where('user_account','=',$data['user_account'])
                ->find();
            if($act_bd['user_qq_id'] != null){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            if($act_bd['user_account'] != null){
                $act_jh = Db::table('ys_login_account')
                    ->where('user_account','=',$data['user_account'])
                    ->setField('user_qq_id',$data['user_qq_id']);
            }else{
                //没有注册过的邮箱
                $act_jh =Db::table('ys_login_account')->insert($data);
            }
            if($act_jh == true){
                // 更新用户状态 账号更新
                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_qq_id'])
                    ->setInc('user_login_num');

                Db::table('ys_login_account')
                    ->where('user_account_id','=',$data['user_qq_id'])
                    ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                //微博更新
                Db::table('ys_login_qq')
                    ->where('user_qq_id','=',$data['user_qq_id'])
                    ->setInc('user_qq_login_num');

                Db::table('ys_login_qq')
                    ->where('user_qq_id','=',$data['user_qq_id'])
                    ->setField('user_qq_last_time',date('Y-m-d H:i:s'));


                $qq_data = Db::table('ys_login_qq')
                    ->where('user_qq_id','=',$data['user_qq_id'])
                    ->find();


                //用户绑定 将用户邮箱存入session
                Session::set('nickname',$qq_data['user_qq_name']);
                Session::set('username',$data['user_account']);
                Session::set('user_qq_id',$data['user_qq_id']);
                Session::set('header_img',$qq_data['user_qq_image_url']);

                $url = "http://plgn.gamepp.com/?s=/index/login/bd_ok";
                return header("Location:".$url);
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

    //直接前往个人中心
    public function gomyinfo(Request $request){
	    if($request->isAjax()){
            $data = $request->param();
            //状态码:用户,微博,微信,qq 0123
            if($data['code_type'] == '1'){
                $id = 'user_wb_id';
            }
            if($data['code_type'] == '2'){
                $id = 'user_wx_id';
            }
            if($data['code_type'] == '3'){
                $id = 'user_qq_id';
            }

            $user_info = Db::table('ys_login_account')
                ->where('user_account','=',$data['username'])
                ->where($id,'=',$data['code_id'])
                ->find();
            //微博
            if($data['code_type'] == '1'){
                //判断绑定成功 没有绑定
                if($user_info == null){
                    return json(['success'=>false,'error'=>'202']); //邮箱还未绑定成功
                }
                //绑定成功
                $wb_info = Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$data['code_id'])
                    ->find();

                //保存session
                Session::set('username',$user_info['user_account']); //邮箱
                Session::set('nickname',$wb_info['user_wb_name']); //微博昵称
                Session::set('header_img',$wb_info['user_wb_image_url']); //微博头像
                Session::set('user_wb_id',$wb_info['user_wb_id']); //微信id
            }

            //微信
            if($data['code_type'] == '2'){
                //判断绑定成功 没有绑定
                if($user_info == null){
                    return json(['success'=>false,'error'=>'202']); //邮箱还未绑定成功
                }
                //绑定成功
                $wx_info = Db::table('ys_login_wx')
                    ->where('user_wx_id','=',$data['code_id'])
                    ->find();

                //保存session
                Session::set('username',$user_info['user_account']); //邮箱
                Session::set('nickname',$wx_info['user_wx_name']); //微博昵称
                Session::set('header_img',$wx_info['user_wx_image_url']); //微博头像
                Session::set('user_wx_id',$wx_info['user_wx_id']); //微信id
            }

            //微信
            if($data['code_type'] == '3'){
                //判断绑定成功 没有绑定
                if($user_info == null){
                    return json(['success'=>false,'error'=>'202']); //邮箱还未绑定成功
                }
                //绑定成功
                $qq_info = Db::table('ys_login_qq')
                    ->where('user_qq_id','=',$data['code_id'])
                    ->find();

                //保存session
                Session::set('username',$user_info['user_account']); //邮箱
                Session::set('nickname',$qq_info['user_qq_name']); //微博昵称
                Session::set('header_img',$qq_info['user_qq_image_url']); //微博头像
                Session::set('user_qq_id',$qq_info['user_qq_id']); //微信id
            }

            return json(['success'=>true,'data'=>$data]);
        }

    }

    //用户协议页面
    public function user_agre(){
        return $this->fetch('user_agre');
    }

    //pc登录成功后 返回参数
    public function pc_login_suc($data = null){
        if($data == null){
            $data['uid'] = input('uid');
            $data['token'] = input('token');
            $data['nickname'] = input('nickname');
            $data['utype'] = input('utype');
            $data['imgurl'] = 'http://plgn.gamepp.com/public/deimg/tx_default.png';
            $data['isemail'] = input('isemail');
            $data['bdsteam'] =input('bdsteam');
        }

        $this->assign('data',$data);
        return $this->fetch('pc_login_suc');
    }

    //pc电脑登录
    public function pc_login(){

	    //用户没有记住密码
        if(Cookie::get('is_rem') != '1'){
            Cookie::set('is_rem','0');
            $data['username'] = Session::get('username');
            $data['pwd'] = Session::get('password');
            $data['rem'] = '0';
        }
        //用户记住密码
        if(Cookie::get('is_rem') == '1'){
            $data['username'] = Session::get('username');
            $data['pwd'] = Session::get('password');
            $data['rem'] = '1';
        }

        //判断用户自动登录
        if (Cookie::get('is_re_lo') == '1'){
                $re_lo = '1';
        }else{
                $re_lo = '0';
        }
        $data['re_lo'] = $re_lo;

        $this->assign('data',$data);
        return $this->fetch('pc_login');
    }


    /***
     * @param $openid   第三方登录openid
     * @param $type  登录 类型  0用户,1微博,2微信,3qq
     * @param $idname  字段名称
     * @param $id  所查关联表id
     * author Fox
     */
    public function headerimg($id,$idname){
        //判断绑定steam
        $isSteam =  Db::table('ys_login_account')
            ->where($idname,'=',$id)
            ->find();
            if($isSteam['user_steam_id'] !=null){
                $sdata = DB::table('ys_login_steam')
                    ->where('user_id','=',$isSteam['user_steam_id'])
                    ->find();
                return $sdata['user_avatarmedium'];
            }else{
                return false;
            }
    }
}