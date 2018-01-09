<?php
/**
 *PHPer:liu
 *time:2017/12/29/029 11:50
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;

use app\common\common\Email;
use app\common\common\OAuthException;
use app\common\common\QQ_LoginAction;
use app\common\common\QQsdk;
use think\Controller;
use think\Db;
use think\Request;
use think\Session;
use app\common\common\Oauth;
use app\common\common\SaeTClientV2;
use think\Url;
url::root('/index.php?s=');

class Login extends Controller {
	//登录页面
	public function index(){
	    if(Session::get('is_rem') !== '1'){
            Session::set('is_rem','0');
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

            //数据验证
            $form_data = [
                'user_account'=>$username,
                'user_pwd'=>$pwd
            ];

            //用户验证
            $rule_user = [
                'user_account' => 'require|max:18|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多18个字符',
                'user_account.min' => '邮箱最少4个字符',
                'user_account.email' => '邮箱格式不正确',
            ];

            //密码验证
            $rule_pwd = [
                'user_pwd' => 'require|max:16|min:6'
            ];
            $msg_pwd= [
                'user_pwd.require' => '密码不能为空',
                'user_pwd.max' => '密码长度为6-16字符',
                'user_pwd.min' => '密码长度为6-16字符'
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
                    Session::set('is_rem','1');  //是否记住密码 是
                    Session::set('username',$username); //记录邮箱名
                    Session::set('password',$pwd);   //记住密码
                }else{
                    Session::set('is_rem','0'); //否
                }

                //自动登录处理
                if($re_lo == '1'){
                    Session::set('is_re_lo','1'); //是
                }else{
                    Session::set('is_re_lo','0'); //否
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
                    return json(['success'=>true,'utype'=>$utype,'uid'=>$username,'token'=>$user_data['user_token'],'nickname'=>$user_data['user_nickname']
,'header_url'=>'']);
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
        //獲取登錄狀態
        $act_type = input('act_type');

        //实例化微博oauth类 获取授权窗口
        $oAuth = new Oauth('2067469895','5b3bd631e64e4c051ee3d3d57bbd5dcd');

        //微博绑定
        if($bd_type == '0'){
            $code_url = $oAuth->getAuthorizeURL("http://plgn.gamepp.com/?s=index/login/weiboLoginCallback/bd_type/{$bd_type}/uemail/{$uemail}/act_type/{$act_type}");
            return header("Location:".$code_url);
        }

        $code_url = $oAuth->getAuthorizeURL("http://plgn.gamepp.com/?s=index/login/weiboLoginCallback/utype/{$utype}");
        return header("Location:".$code_url);
    }


    public function weiboLoginCallback(Request $request){

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
            $user_message = $oAuthResult->show_user_by_id($uid_get['uid']);
            
            //判断第三方是否登录过
            $returnUserInfo = Db::table('ys_login_wb')
                ->where('user_wb_openid','=',$user_message['id'])
                ->find();

            //第三方已经登录
            if ($returnUserInfo==true){

                //获取用户 是否绑定
                $user_info = Db::table('ys_login_account')
                        ->where('user_wb_id','=',$returnUserInfo['user_wb_id'])
                        ->find();

                //第三方不是首次登陆
                if($user_info == true){
                    // 更新用户状态 账号更新
                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$returnUserInfo['user_wb_id'])
                        ->setInc('user_login_num');

                    Db::table('ys_login_account')
                        ->where('user_account_id','=',$returnUserInfo['user_wb_id'])
                        ->setField('user_last_login_time',date('Y-m-d H:i:s'));

                    //微博更新
                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$returnUserInfo['user_wb_id'])
                        ->setInc('user_wb_login_num');

                    Db::table('ys_login_wb')
                        ->where('user_wb_id','=',$returnUserInfo['user_wb_id'])
                        ->setField('user_wb_last_time',date('Y-m-d H:i:s'));

                    //判断客户端登录
                    $utype = input('utype');
                    if ($utype == '1'){
                        $user_info = Db::table('ys_login_wb')
                            ->where('user_wb_id','=',$returnUserInfo['user_wb_id'])
                            ->find();

                        $data = array(
                            'uid' => $user_info['user_wb_openid'],
                            'header_url'=> $user_info['user_wb_image_url'],
                            'nickname'=>$user_info['user_wb_name']
                        );

                        return json(['success'=>true,'utype'=>$utype,'data'=>$data]);
                    }
                    Session::set('username',$user_info['user_account']);
                    Session::set('user_wb_id',$returnUserInfo['user_wb_id']);
                    $url = "http://plgn.gamepp.com/?s=/index/personal/my_info/act_type/1";
                    return header("Location:".$url);

                }else{
                    $bd_info = $request->param();
                    $bd_info['bd_type'] = '';
                    //微博绑定
                    if($bd_info['bd_type'] == '0'){
                        //获取user_wb_id
                        Db::table('ys_login_account')
                        ->where('user_account','=',$bd_info['uemail'])
                        ->setField('user_wb_id',$returnUserInfo['user_wb_id']);
                        $url = "http://plgn.gamepp.com/index.php?s=/index/personal/my_info/act_type/{$bd_info['act_type']}";
                        return header("Location:".$url);
                    }
                    //用户没有绑定邮箱 获取自增id
                    Session::set('wbcode',$returnUserInfo['user_wb_id']);
                    //第一次没有邮箱 绑定邮箱
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email1/wbcode/{$returnUserInfo['user_wb_id']}";
                    return Header("Location: $url");
                }
            }else{
                //如果微博用户第一次登录 保存信息
                $userInfo['user_wb_name']    = $user_message['screen_name'];   //微博昵称
                $userInfo['user_wb_image_url']    = $user_message['profile_image_url'];   //微博头像
                $userInfo['user_wb_openid']    = $user_message['id'];   //openid
                $userInfo['user_wb_auth_time'] = date('Y-m-d H:i:s'); //开始授权时间
                $userInfo['user_wb_last_time'] = date('Y-m-d H:i:s'); //最后登录时间


                $bd_info = $request->param();
                //微博绑定
                if($bd_info['bd_type'] == '0'){
                    //存入新數據
                    $data = Db::table('ys_login_wb')->insert($userInfo);

                    $user_info = Db::table('ys_login_wb')
                            ->where('user_wb_openid','=',$userInfo['user_wb_openid'])
                            ->find();
                        //关联
                    Db::table('ys_login_account')
                            ->where('user_account','=',$bd_info['uemail'])
                            ->setField('user_wb_id', $user_info['user_wb_id']);
                    $url = "http://plgn.gamepp.com/index.php?s=/index/personal/my_info/act_type/{$bd_info['act_type']}";
                    return header("Location:".$url);
                }


                $data = Db::table('ys_login_wb')->insert($userInfo);
                if ($data == true){
                    //获取自增id
                    Session::set('wbcode',$returnUserInfo['user_wb_id']);

                    //第一次没有邮箱 绑定邮箱
                    $url = "http://plgn.gamepp.com/?s=index/login/bd_email1/wbcode/{$returnUserInfo['user_wb_id']}";
                    return Header("Location: $url");
                }
            }
        }
    }

    //发送验证邮箱
    public function bd_email1(Request $request){
        if($request->isAjax()){
            $wb_info = Session::get('wbcode');
            $username = input('post.username');
            $check_rem = input('post.check_rem');

            //数据验证
            $form_data = [
                'user_account'=>$username,
            ];
            //用户密码分开验证方便前台返回
            //用户验证
            $rule_user = [
                'user_account' => 'require|max:18|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多18个字符',
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
                $user_active_code = substr(md5($username.time()),-15);

                //保存入库激活码
                $user_act['user_wb_act_code'] = $user_active_code;
                $user_act['user_wb_act_code_time'] = time()+7200;


                $act_email = Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$wb_info)
                    ->setField($user_act);

                //调用邮箱类
                if($act_email == true){
                    //随机密码
                    $pwd = mt_rand(10000000,99999999);

                    $email = new Email();
                    //判断邮箱是否存在  存在就不发送密码密码
                    $account = Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->find();
                    if($account['user_account'] != null && $account['user_wb_id'] == null){
                        $pwd = mt_rand(1,10000);
                        $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$wb_info}/uCode/{$user_active_code}/wbrand/{$pwd}/user_email/{$username}/act_bd_type/1";
                        $email->mail_certification($username,$confirm_url);
                    }

                    $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$wb_info}/uCode/{$user_active_code}/wbrand/{$pwd}/user_email/{$username}/act_bd_type/1";
                    $email->mail_certification_bind($username,$confirm_url,$pwd);

                    if($email == true){
                        return json(['success'=>true,'user_wb_id'=>$wb_info,'uCode'=>$user_active_code,'username'=>$username]);
                    }
                }
            }else{
                //验证不通过
                return json(['success'=>false,'error'=>'300','info'=>$result_user]);
            }
        }
        return $this->fetch();
    }

    //邮箱重新发送
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
            $user_active_code = substr(md5($username.time()),-15);

            //保存入库激活码
            $user_act['user_wb_act_code'] = $user_active_code;
            $user_act['user_wb_act_code_time'] = time()+7200;

            $act_email = Db::table('ys_login_wb')
                ->where('user_wb_id','=',$user_wb_id)
                ->setField($user_act);

            //随机密码
            $pwd = mt_rand(10000000,99999999);

            $email = new Email();
            $confirm_url ="http://plgn.gamepp.com/?s=index/login/act_code/wbcode/{$user_wb_id}/uCode/{$user_active_code}/wbrand/{$pwd}/user_email/{$username}/act_bd_type/1";
            $email->mail_certification_bind($username,$confirm_url,$pwd);

            if($email == true){
                return json(['success'=>true,'user_wb_id'=>$user_wb_id,'uCode'=>$user_active_code,'wbrand'=>$pwd]);
            }
        }
    }

    //第三方邮箱绑定激活
    public function act_code(Request $request){
	    //获取参数
        $info = $request->param();
        //act_type:1 微博 绑定未注册账号
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
            $act_code= Db::table('ys_login_wb')
                ->where('user_wb_id','=',$info['wbcode'])
                ->field('user_wb_act_code_time')
                ->find();

            if(time() > $act_code['user_wb_act_code_time']){
                $url = "http://plgn.gamepp.com/?s=/index/login/bd_no";
                return header("Location:".$url);
            }

            //产生盐值
            $salt  = substr(time(),-6);

            //随机昵称
            $rand_nickname  = "plgn_".mt_rand(10000,99999).substr(time(),-4);
            $data['user_nickname'] = $rand_nickname;

            $data['user_account'] = $info['user_email'];
            $data['user_pwd'] = md5($info['wbrand'].$salt);
            $data['user_salt'] =$salt;
            $data['user_wb_id'] = $info['wbcode'];
            $data['user_create_time'] = date('Y-m-d H:i:s');
            $data['user_is_act'] = '1';


            //获取密码长度,判断邮箱是否存在

            if(strlen($info['wbrand']) < 6){
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
                Session::set('username',$wb_data['user_wb_name']);
                Session::set('email',$data['user_account']);
                Session::set('user_wb_id',$data['user_wb_id']);

                $url = "http://plgn.gamepp.com/?s=/index/login/bd_ok/act_type/1";
                return header("Location:".$url);
            }
        }

    }



    //微信回调地址
    public function wxCallback(){
        echo '微信回调地址';
    }
    //qq授权页面
    public function qqlogin(){
	    $app_id = '101456064';
        $redirect = 'http://plgn.gamepp.com/?s=/index/login/qqCallback';
        //$redirect 为回调地址  $app_id 应用编号
        $url = 'https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=' . $app_id . '&redirect_uri=' . $redirect;
        header('Location:' . $url);
    }
    public function qqCallback(){
        if(isset($_GET['code'])) {
            $qq_sdk = new QQsdk();
            $token = $qq_sdk->get_user_info($_GET['code']);
            dump($tokne);
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


    //pc电脑登录
    public function pc_login(){

	    //用户没有记住密码
        if(Session::get('is_rem') !== '1'){
            Session::set('is_rem','0');

            $data['username'] = Session::get('username');
            $data['pwd'] = Session::get('password');
            $data['rem'] = '0';
        }
        //用户记住密码
        if(Session::get('is_rem') == '1'){
            $data['username'] = Session::get('username');
            $data['pwd'] = Session::get('password');
            $data['rem'] = '1';
        }
        //判断用户自动登录
        if (Session::get('is_re_lo') == '1'){
                $re_lo = '1';
        }else{
                $re_lo = '0';
        }
        $data['re_lo'] = $re_lo;

        $this->assign('data',$data);
        return $this->fetch('pc_login');
    }

    public function pc_login_check(){

    }
}