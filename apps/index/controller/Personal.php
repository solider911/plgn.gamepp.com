<?php
/**
 *PHPer:liu
 *time:2018/1/4/004 16:11
 *motto:Buddha bless, never bug!
 */
namespace app\index\controller;
use app\common\Base;
use app\common\common\Email;
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


       //获取用户数据
        $nickname = Db::table('ys_login_account')
            ->where('user_account','=',$username)
            ->find();
        if($username == null){
            $data['is_login'] = '0'; //0为没登录
            return $this->fetch();
        }else{
            $data['is_login'] = '1'; //1为登录
            //判断用户是否完善   判断用户是否完善
            if($nickname['user_nickname'] != null){
                $data['ws_info'] = '1';
                //用户性别
                $data['user_sex'] = $nickname['user_sex'];
            }else{
                $data['ws_info'] = '0';
                $data['user_sex'] = $nickname['user_sex'];
            }
        }

        //用户普通登录
        if($type['act_type'] == '0'){
            $data['header_img'] = "__IMG__/de_he_img.jpg";  //默认头像
            //判断用户有没有昵称
            if($nickname['user_nickname'] != null){
                $data['nickname'] = $nickname['user_nickname'];
            }else{
                $data['nickname'] = '';
            }
        }

       //1为微博绑定邮箱
       if($type['act_type'] == '1'){
            //获取头像
           $header_img = Db::table('ys_login_wb')
               ->where('user_wb_id','=', Session::get('user_wb_id'))
               ->find();
           $data['header_img'] = $header_img['user_wb_image_url'];

            //判断用户有没有昵称
           $nickname = Db::table('ys_login_wb')
               ->alias('w')
               ->join('ys_login_account a','w.user_wb_id = a.user_wb_id')
               ->where('w.user_wb_id','=','a.user_account_id')
               ->find();
           if($nickname['user_nickname'] != null){
               $data['nickname'] = $nickname['user_nickname'];
               $data['user_sex'] = $nickname['user_sex'];
           }else{
               $data['nickname'] = $nickname[''];
               $data['user_sex'] = $nickname['user_sex'];
           }
       }


       //判断第三方是否绑定
       $bd_type = DB::table('ys_login_account')
           ->where('user_account','=',Session::get('username'))
           ->find();

        //预设为1
        $data['user_wb_id'] = '1';
        $data['user_qq_id'] = '1';
        $data['user_wx_id'] = '1';
        $data['user_steam_id'] = '1';
        //微博
        if($bd_type['user_wb_id'] == null){
            $data['user_wb_id'] = '0';
        }
        //qq
        if($bd_type['user_qq_id'] == null){
            $data['user_qq_id'] = '0';
        }
        //微信
        if($bd_type['user_wx_id'] == null){
            $data['user_wx_id'] = '0';
        }
        //steam
        if($bd_type['user_steam_id'] == null){
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
                'user_nickname.max' => '16',
                'user_nickname.min' => '用户昵称最少4个字符'
            ];


            //进行验证
            $result = $this->validate($form_data,$rule_user,$msg_user);  //用户
            if($result == true){
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
                $act['user_active_code'] = substr(md5($n_username.time()),-15);
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
            $url = "http://plgn.gamepp.com/index.php?s=/index/personal/cemail_ok_j";
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

    //取消绑定社交账号
    public function bd_wb_type_del(Request $request){
        if($request->isAjax()){
            $username_email = input('post.username_email');
            $user_account = Db::table('ys_login_account')
                ->where('user_account','=',$username_email)
                ->find();
            if($user_account['user_wb_id'] != null){
                $wb_del = Db::table('ys_login_wb')
                    ->where('user_wb_id','=',$user_account['user_wb_id'])
                    ->setField('user_wb_id','');
                if($wb_del == true){
                    return json(['success'=>true]);
                }else{
                    return json(['success'=>false,'error'=>'取消关联失败']);
                }
            }else{
                return json(['success'=>false,'error'=>'取消关联失败']);
            }

        }


    }

    //修改密码
    public function up_pwd(Request $request){
        $y_pwd = input('post.y_pwd');
        $pwd = input('post.pwd');
        $pwd2 = input('post.pwd2');


        //数据验证
        $form_data = [
            'user_pwd'=>$pwd,
            'user_pwd2'=>$pwd2
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
        $result_pwd = $this->validate($form_data,$rule_pwd,$msg_pwd);



        if($result_pwd == true){
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
                return json(['success'=>true]);
            }
        }else{
            return json(['success'=>false,'error'=>'300','info'=>$result_pwd]);
        }
    }

    //退出
    public function logout(){
        Session::set('username',null);
        Session::set('password',null);
        Session::set('is_rem','0');
        $url = "http://gamepp.com/chichken/youxijj.html";
        return Header("Location: $url");
    }
}