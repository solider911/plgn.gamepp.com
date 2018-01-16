<?php
/**
 *PHPer:liu
 *time:2018/1/4/004 16:11
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;
use app\common\Base;
use app\common\common\Email;
use think\Cookie;
use think\Db;
use think\Request;
use think\Session;
use think\Url;
url::root('/index.php?s=');
class Personal extends Base {

    //个人信息首页
    public function my_info(Request $request){
       //设定用户登录状态 act_type:
       $type = $request->param();
       $username =  Session::get('username');

       //dump($username);return;
       //获取用户数据
        $user_data = Db::table('ys_login_account')
            ->where('user_account','=',$username)
            ->find();

        if($username == null){
            $data['is_login'] = '0'; //0为没登录
            $this->assign('data',$data);
            return $this->fetch();
        }else{
            $data['is_login'] = '1'; //1为登录
            //判断用户是否完善   判断用户是否完善
            if($user_data['user_nickname'] != null){
                $data['ws_info'] = '1';
                //用户性别
                $data['user_sex'] = $user_data['user_sex'];
            }else{
                $data['ws_info'] = '0';
                $data['user_sex'] = $user_data['user_sex'];
            }
        }

        //第三方登录
        if(Session::get('header_img') != null && Session::get('nickname') != null){

            $data['header_img'] = Session::get('header_img');
            $data['nickname'] = Session::get('nickname');
        }else{
            //用户普通登录
            $data['header_img'] = "http://plgn.gamepp.com/public/deimg/tx_default.png";  //默认头像
            $data['nickname'] = $user_data['user_nickname'];
        }

       //判断第三方是否绑定
        //预设为1
        $data['user_wb_id'] = '1';
        $data['user_qq_id'] = '1';
        $data['user_wx_id'] = '1';
        $data['user_steam_id'] = '1';
        //微博
        if($user_data['user_wb_id'] == null){
            $data['user_wb_id'] = '0';
        }
        //qq
        if($user_data['user_qq_id'] == null){
            $data['user_qq_id'] = '0';
        }
        //微信
        if($user_data['user_wx_id'] == null){
            $data['user_wx_id'] = '0';
        }
        //steam
        if($user_data['user_steam_id'] == null){
            $data['user_steam_id'] = '0';
        }


        $this->assign('data',$data);
        return $this->fetch();
    }

    //修改个人信息

    public function up_my_info(Request $request){
        if($request->isAjax()){
            $nickname = input('post.nickname');
            $user_sex = input('post.user_sex');
            $email = input('post.email');

            //数据验证
            $form_data = [
                'user_nickname'=>$nickname,
                'user_sex'=>$user_sex,
            ];

            //用户验证
            $rule_user = [
                'user_nickname' => 'require|max:16|min:4',
            ];
            $msg_user= [
                'user_nickname.require' => '用户昵称不能为空',
                'user_nickname.max' => '用户昵称最少64个字符',
                'user_nickname.min' => '用户昵称最少4个字符'
            ];


            //进行验证
            $result = $this->validate($form_data,$rule_user,$msg_user);  //用户
            if($result == true){
                //判断昵称是否存在
                $user_nickname = Db::table('ys_login_account')
                    ->where('user_nickname','=',$nickname)
                    ->find();

                if($user_nickname != null){
                    return json(['success'=>false,'error'=>'202']);
                }

                $per_info = Db::table('ys_login_account')
                    ->where('user_account','=',$email)
                    ->setField($form_data);
                if($per_info == true){
                    return(['success'=>true]);
                }
            }else{
                return json(['success'=>false,'error'=>'300','info'=>$result]);
            }
        }
    }

    //更换邮箱首页
    public function cemail(Request $request){
        if($request->isAjax()){
            $n_username = input('post.username');
            $check_rem = input('post.check_rem');

            //数据验证
            $form_data = [
                'user_account'=>$n_username,
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
                //新老邮箱不能相同
                $y_username = Session::get('username');

                if($n_username == $y_username){
                    return json(['success'=>false,'error'=>'204']);
                }

                $bd_email =  Db::table('ys_login_account')
                    ->where('user_account','=',$n_username)
                    ->find();

                if($bd_email == true){
                    return json(['success'=>false,'error'=>'206']);
                }

                //邮箱激活随机码
                $act['user_active_code'] = hash("sha1",$n_username.time());
                //激活码有效时间
                $act['user_act_code_time'] = time()+7200;


                //激活码
                 Db::table('ys_login_account')
                    ->where('user_account','=',$y_username)
                    ->setField($act);


                $email = new Email();
                $confirm_url ="http://plgn.gamepp.com/?s=index/personal/sc_key/n_username/{$n_username}/uCode/{$act['user_active_code']}/y_username/{$y_username}";
                $email->mail_certification_cemail($n_username,$confirm_url);
                if($email == true){
                        return json(['success'=>true,'n_username'=>$n_username,'uCode'=>$act['user_active_code'],'y_username'=>$y_username]);
                    }
            }else{
                //验证不通过
                return json(['success'=>false,'error'=>'300','info'=>$result_user]);
            }
        }
        return $this->fetch();
    }

    //确认更换邮箱
    public function qr_email(Request $request){
        if($request->isAjax()){
            $info = $request->param();
            //判断邮箱能否更换
            $qr_email_is =  Db::table('ys_login_account')
                ->where('user_account','=',$info['y_user_email'])
                ->where('user_active_code','=',$info['user_code'])
                ->field('user_is_act_code')
                ->find();

            if($qr_email_is['user_is_act_code'] != '1'){
                return json(['success'=>false,'error'=>'204']);
            }

            $qr_email = Db::table('ys_login_account')
                ->where('user_account','=',$info['y_user_email'])
                ->where('user_active_code','=',$info['user_code'])
                ->setField('user_account',$info['n_user_email']);

            if($qr_email == true){
                //将邮箱改回未确认修改状态
                $qr_email_is1 =  Db::table('ys_login_account')
                    ->where('user_account','=',$info['n_user_email'])
                    ->setField('user_is_act_code','0');
                if($qr_email_is1 == true){
                    return json(['success'=>true]);
                }

            }else{
                return json(['success'=>false,'error'=>'202']);
            }
        }
    }

    //点击链接生成秘钥
    public function sc_key(Request $request){
        $info = $request->param();
        $qr_email = Db::table('ys_login_account')
            ->where('user_account','=',$info['y_username'])
            ->where('user_active_code','=',$info['uCode'])
            ->setField('user_is_act_code','1');

        if($qr_email == true){
            Session::set('username',$info['n_username']);
            $url = "http://plgn.gamepp.com/?s=/index/personal/cemail_ok_j";
            Header("Location:".$url);
        }
    }

    //修改成功页面
    public function cemail_ok(){
        return $this->fetch();
    }

    //邮箱验证页面
    public function cemail_ok_j(){
        return $this->fetch();
    }


    //绑定社交账号
    public function bd_email_v(){
        return $this->fetch();
    }

    //取消绑定微博账号
    public function bd_wb_type_del(Request $request){
        if($request->isAjax()){
            $username_email = input('post.username_email');
            $user_account = Db::table('ys_login_account')
                ->where('user_account','=',$username_email)
                ->find();

            if($user_account['user_wb_id'] != null){
                $wb_del = Db::table('ys_login_account')
                    ->where('user_wb_id','=',$user_account['user_wb_id'])
                    ->setField('user_wb_id',null);
                if($wb_del == true){
                    return json(['success'=>true]);
                }else{
                    return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
                }
            }else{
                return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
            }

        }

    }

    //取消绑定微信账号
    public function bd_wx_type_del(Request $request){
        if($request->isAjax()){
            $username_email = input('post.username_email');
            $user_account = Db::table('ys_login_account')
                ->where('user_account','=',$username_email)
                ->find();

            if($user_account['user_wx_id'] != null){
                $wb_del = Db::table('ys_login_account')
                    ->where('user_wx_id','=',$user_account['user_wx_id'])
                    ->setField('user_wx_id',null);
                if($wb_del == true){
                    return json(['success'=>true]);
                }else{
                    return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
                }
            }else{
                return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
            }

        }

    }

    //取消绑定微信账号
    public function bd_qq_type_del(Request $request){
        if($request->isAjax()){
            $username_email = input('post.username_email');
            $user_account = Db::table('ys_login_account')
                ->where('user_account','=',$username_email)
                ->find();

            if($user_account['user_qq_id'] != null){
                $wb_del = Db::table('ys_login_account')
                    ->where('user_qq_id','=',$user_account['user_qq_id'])
                    ->setField('user_qq_id',null);
                if($wb_del == true){
                    return json(['success'=>true]);
                }else{
                    return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
                }
            }else{
                return json(['success'=>false,'error'=>'取消关联失败,刷新页面重试']);
            }
        }
    }



    //修改密码
    public function up_pwd(Request $request){
        $y_pwd = input('post.y_pwd');
        $pwd = input('post.pwd');
        $pwd2 = input('post.pwd2');
        $pwd_len = input('post.$pwd_len');


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
            /*if($pwd_len < 6 || $pwd_len > 16){
                return json(['success'=>false,'error'=>'208']); //密码错误
            }*/
            $username = Session::get('username');

            //核对用户
            //获取盐值
            $salt = Db::table('ys_login_account')
                ->where('user_account','=',$username)
                ->field('user_salt')
                ->find();
            //转换成加密密码
            $z_pwd = md5($y_pwd.$salt['user_salt']);
            
            $check_pwd = Db::table('ys_login_account')
                ->where('user_account','=',$username)
                ->where('user_pwd','=',$z_pwd)
                ->find();

            //密码错误
            if($check_pwd != true  ){
                return json(['success'=>false,'error'=>'204']); //密码错误
            }

            if($y_pwd == $pwd){
                return json(['success'=>false,'error'=>'206']); //密码一样
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
                ->setField($data);
            if($info == true) {
                Session::set('username',null);
                return json(['success'=>true]);
            }
        }else{
            return json(['success'=>false,'error'=>'300','info'=>$result_pwd]);
        }
    }

    //退出
    public function logout(){
        Session::set('username',null);
        Session::set('nickname',null);
        Session::set('user_wx_id',null);
        Session::set('header_img',null);
        $url = "http://gamepp.com/chichken/youxijj.html";
        return Header("Location: $url");
    }
}