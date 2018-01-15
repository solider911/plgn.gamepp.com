<?php
namespace app\index\controller;
use think\Controller; // 引入Controllerle类
use think\Db;  // 引入数据库

class Test extends Controller
{
    public function index($name="world")
    {
        $this->assign('name', $name);
        return $this->fetch();
    }

    public function dbtest(){
        $data_wx = Db::name("login_wx")->find(); // name表名（不包含表前缀）

//        print_r($data_wx);

        $this->assign("result", $data_wx);
        return $this->fetch();
    }

    public function outstr($str){

        if (empty($str))
            return "str is empty";

        return $str;
    }
}
