<?php
/**
 *PHPer:liu
 *time:2017/12/29/029 12:01
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;

use think\Controller;
use think\Db;
use think\Request;
use think\Url;
use app\common\common\Email;
url::root('/index.php?s=');


class Register extends Controller{
    public function aaemail(){
        $email = new Email();
       $email->mail_certification("1499622690@qq.com", "www.haha.com");
    }
    //注册页面
    public function index(){
        return $this->fetch();
    }

    //用户注册

    /**
     * @param \think\Request $request
     *
     * @return \think\response\Json
     * author Fox
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    public function register(Request $request){
        if($request->isAjax()){
            $username = input('post.username');
            $pwd = input('post.pwd');
            $pwd2 = input('post.pwd2');
            $check_rem = input('post.check_rem');

            //数据验证
            $form_data = [
                'user_account'=>$username,
                'user_pwd'=>$pwd,
                'user_pwd2'=>$pwd
            ];
            $rule_user = [
                'user_account' => 'require|max:18|min:4|email',
            ];
            $msg_user= [
                'user_account.require' => '邮箱不能为空',
                'user_account.max' => '邮箱最多18个字符',
                'user_account.min' => '邮箱最少4个字符',
                'user_account.email' => '邮箱格式不正确',
            ];

            $rule_pwd = [
                'user_pwd' => 'require|max:16|min:6',
                'user_pwd2'=>'confirm:user_pwd'
            ];
            $msg_pwd= [
                'user_pwd.require' => '密码不能为空',
                'user_pwd.max' => '密码长度为6-16字符',
                'user_pwd.min' => '密码长度为6-16字符',
                'user_pwd2.confirm' => '两次输入密码不一致',
            ];

            //进行验证
            $result_user = $this->validate($form_data,$rule_user,$msg_user);
            $result_pwd = $this->validate($form_data,$rule_pwd,$msg_pwd);

            if($result_user === true && $result_pwd === true){
                if($check_rem != '1'){
                    return json(['success'=>false,'error'=>'204']);
                }
                //判断用户是否存在
                $user_account = Db::table('ys_login_account')
                    ->where('user_account','=',$username)
                    ->find();
                if($user_account != null){
                    return json(['success'=>false,'error'=>'206']);
                }

                //产生盐值
                $salt  = substr(time(),-6);

                //邮箱激活随机码
                $user_active_code = substr(md5($username.time()),-15);

                //注册信息
                $data = array(
                    'user_account'=>$username,
                    'user_pwd'=>md5($pwd.$salt),
                    'user_salt'=>$salt,
                    'user_create_time'=>date('Y-m-d H:i:s'),
                    'user_active_code'=>$user_active_code
                );

                $reg = Db::table('ys_login_account')->insert($data);
                if($reg == true){
                    $email = new Email();
                    $confirm_url ="http://plgn.gamepp.com/?s=index/register/email/username/{$username}/uCode/{$user_active_code}";
                    $email->mail_certification($username,$confirm_url);
                    if($email == true){
                        return json(['success'=>true,'username'=>$username,'uCode'=>$user_active_code]);
                    }

                }else{
                    return json(['success'=>false,'error'=>'208']);
                }
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

    //邮箱激活
    public function check_email(){
        return $this->fetch();
    }


    /**
     * @return mixed|string
     * author Fox
     * @throws \think\Exception
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     * @throws \think\exception\PDOException
     */

    //邮箱激活
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
            $str  = Db::table('ys_login_account')
                ->where('user_account','=',$username)
                ->where('user_active_code','=',$user_active_code)
                ->setField('user_is_act','1');
            if ($str == true) {
                return $this->fetch('reg_ok');
            }
        }
    }

    //邮箱重新发送
    public function cx_email(Request $request){
        $data = $request->param();
        //获取邮件激活信息
        $username = $data['username'];
        $user_active_code =$data['uCode'];

        //邮箱激活随机码
        $cx_user_active_code = substr(md5($username.time()),-15);

        $reg = Db::table('ys_login_account')
            ->where('user_account','=',$username)
            ->where('user_active_code','=',$user_active_code)
            ->setField('user_active_code',$cx_user_active_code);
        if($reg == true) {
            $email       = new Email();
            $confirm_url = "http://plgn.gamepp.com/?s=index/register/email/username/{$username}/uCode/{$cx_user_active_code}";
            $email->mail_certification($username, $confirm_url);
            if ($email == true) {
                $url = "http://plgn.gamepp.com/?s=index/register/check_email/username/{$username}/uCode/{$cx_user_active_code}";
                header("Location:".$url);
            }
        }else{
            return '失败';
        }
    }

}