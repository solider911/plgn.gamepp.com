<?php
/**
 *PHPer:liu
 *time:2018/1/2/002 15:09
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;

use think\Controller;
use think\Db;
use think\Request;
use think\Url;
use app\common\common\Email;
url::root('/index.php?s=');

class Gbpwd extends Controller {

    //找回密码页面
    public function index(){
        return $this->fetch();
    }

    public function gbpwdE(Request $request){
        if($request->isAjax()) {
            $username = input('post.username');
            //数据验证
            $form_data = [
                'user_account' => $username,
            ];
            //邮箱验证
            $rule_user = [
                'user_account' => 'require|max:18|min:4|email',
            ];
            $msg_user  = [
                'user_account.require' => '邮箱不能为空',
                'user_account.max'     => '邮箱最多18个字符',
                'user_account.min'     => '邮箱最少4个字符',
                'user_account.email'   => '邮箱格式不正确',
            ];

            //进行验证
            $result_user = $this->validate($form_data, $rule_user, $msg_user);

            if($result_user === true){
                //判断用户是否存在
                $user = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();
                if($user == null){
                    return json(['success'=>false,'error'=>'202']); //邮箱不存在
                }
                //判断用户是否被激活
                if($user['user_is_act'] != '1'){
                    return json(['success'=>false,'error'=>'203']); //用户未激活
                }

                //判断用户是否被冻结
                if($user['user_is_free'] != '1'){
                    return json(['success'=>false,'error'=>'204']); //用户被冻结
                }

                //邮箱激活随机码
                $user_active_code = hash("sha1",$username.time());

                Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->setField('user_active_code',$user_active_code);

                //发送找回密码邮箱
                $email = new Email();
                $confirm_url ="http://plgn.gamepp.com/?s=index/gbpwd/email/username/{$username}/uCode/{$user_active_code}";
                $email->mail_certification_gbpwd($username,$confirm_url);
                if($email == true){
                    return json(['success'=>true,'username'=>$username,'uCode'=>$user_active_code]);
                }
            }else{
                //填写验证失败
                if($result_user !== true){
                    return json(['success'=>false,'error'=>'300','info'=>$result_user]);
                }
            }
        }
    }

    //找回密码重新发送页面
    public function checkpwdE(){
        return $this->fetch();
    }

    //修改密码页面
    public function xgpwd(Request $request){

        if($request->isAjax()){

            $data = $request->param();
            //获取邮件激活信息
            $user_active_code =$data['uCode'];
           $username = $data['username'];


            $pwd = input('post.pwd');
            $pwd2 = input('post.pwd2');
            $pwd_len = input('post.pwd_len');


            //数据验证
            $form_data = [
                'user_pwd'=>$pwd,
                'user_pwd2'=>$pwd2
            ];
            $rule_pwd = [
                'user_pwd' => 'require',
                'user_pwd2'=>'confirm:user_pwd'
            ];
            $msg_pwd= [
                'user_pwd.require' => '密码不能为空',
                'user_pwd2.confirm' => '两次输入密码不一致',
            ];
            //进行验证
            $result_pwd = $this->validate($form_data,$rule_pwd,$msg_pwd);

            if($result_pwd == true){

                if($pwd_len<6 || $pwd_len>16){
                    return json(['success'=>false,'error'=>'206']);
                }

                //产生盐值
                $salt  = substr(time(),-6);

                $data = array(
                    'user_pwd'=>md5($pwd.$salt),
                    'user_salt'=>$salt,
                );

                //根据$active_code和$user_id查询是否存在一条记录，存在修改密码
                $info  = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->where('user_active_code','=',$user_active_code)
                    ->setField($data);

                $info  = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    //->where('user_active_code','=',$user_active_code)
                    ->find();

                return json(['success'=>true,'data'=>$user_active_code]);

                if($info == true) {
                    Db::table('ys_login_account')
                        ->where('user_account','=',$username)
                        ->setField('user_active_code',null);
                    return json(['success'=>true]);
                }else{
                    return json(['success'=>false,'error'=>'204']);
                }
            }else{
                return json(['success'=>false,'error'=>'202','info'=>$result_pwd]);
            }
        }
    }

    //密码找回成功页面
    public function gbpwd_ok(){
        return $this->fetch();
    }

    //找回密码邮箱激活
    public function email(Request $request){
        $data = $request->param();
        //获取邮件激活信息
        $user_active_code =$data['uCode'];
        $username = $data['username'];

        //根据$active_code和$user_id查询是否存在一条记录，存在就激活
        $info = Db::table('ys_login_account')
            ->where('user_account','=',$username)
            ->where('user_active_code','=',$user_active_code)
            ->find();

        if($info == true) {
            return $this->fetch('xgpwd');
        }
    }

    //邮箱重新发送
    public function cx_email(Request $request){
        $data = $request->param();
        //获取邮件激活信息
        $username = $data['username'];
        $user_active_code =$data['uCode'];

        //邮箱激活随机码
        $cx_user_active_code = hash("sha1",$username.time());

        $reg = Db::table('ys_login_account')
            ->where('user_account','=',$username)
            ->where('user_active_code','=',$user_active_code)
            ->setField('user_active_code',$cx_user_active_code);
        if($reg == true) {
            $email       = new Email();
            $confirm_url = "http://plgn.gamepp.com/?s=index/gbpwd/email/username/{$username}/uCode/{$cx_user_active_code}";
            $email->mail_certification_gbpwd($username, $confirm_url);
            if ($email == true) {
                $url = "http://plgn.gamepp.com/?s=index/gbpwd/checkpwde/username/{$username}/uCode/{$cx_user_active_code}";
                header("Location:".$url);
            }
        }
    }

}
