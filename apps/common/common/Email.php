<?php
namespace app\common\common;
include_once './apps/common/plugin/aliyun-php-sdk-core/Config.php';
use Dm\Request\V20151123\SingleSendMailRequest;
use Dm\Request\V20151123\BatchSendMailRequest;
use Dm\Request\V20151123\SingleSendSmsRequest;
class Email {
//mail_certification("1499622690@qq.com", "www.haha.com");

// 注册认证
function mail_certification($mail_to, $mail_content){
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", "LTAIAjLeruKbDb1l", "FJAlNoN7WK9tQx8GYDX7TMMROu5c45");
        $client = new \DefaultAcsClient($iClientProfile);
        $request = new SingleSendMailRequest();



        $request->setAccountName("mpubg@m.plgn.gamepp.com");
        $request->setFromAlias("绝地求生超级助手");
        $request->setAddressType(1);
        $request->setTagName("mailspubg");
        $request->setReplyToAddress("true");
        $request->setToAddress($mail_to);
        $request->setSubject("绝地求生超级助手用户系统");

        try {

            $mail_body = "尊敬的{$mail_to}：</br>

                          您好！感谢您注册成为绝地求生超级助手用户系统的一员。这是一封注册确认邮件，请点击以下链接确认：</br>
                          
                          <a href=''>{$mail_content}</a> </br>
                          
                          如果链接不能点击，请复制地址到浏览器，然后直接打开。</br>
                          
                          （这是一封自动产生的email，请勿回复。）";

            $request->setHtmlBody($mail_body);
            $response = $client->getAcsResponse($request);

            return true;
            //echo "发送完成"."<br>";
            //print_r($response);
        }
        catch (ClientException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }
        catch (ServerException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }

    }


    // 绑定认证
    function mail_certification_bind($mail_to, $mail_content, $user_pwd){
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", "LTAIAjLeruKbDb1l", "FJAlNoN7WK9tQx8GYDX7TMMROu5c45");
        $client = new \DefaultAcsClient($iClientProfile);
        $request = new SingleSendMailRequest();



        $request->setAccountName("mpubg@m.plgn.gamepp.com");
        $request->setFromAlias("绝地求生超级助手");
        $request->setAddressType(1);
        $request->setTagName("mailspubg");
        $request->setReplyToAddress("true");
        $request->setToAddress($mail_to);
        $request->setSubject("绝地求生超级助手用户系统");

        try {

            $mail_body = "尊敬的{$mail_to}：</br>

                          您好！感谢您注册成为绝地求生超级助手用户系统的一员。这是一封注册确认邮件，请点击以下链接确认：</br>
                          
                          <a href=''>{$mail_content}</a> </br>
                          
                          您的初始密码为：{$user_pwd}，请尽快前往个人中心修改！
                          
                          如果链接不能点击，请复制地址到浏览器，然后直接打开。</br>
                          
                         （这是一封自动产生的email，请勿回复。）";

            $request->setHtmlBody($mail_body);
            $response = $client->getAcsResponse($request);

            return true;
            //echo "发送完成"."<br>";
            //print_r($response);
        }
        catch (ClientException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }
        catch (ServerException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }

    }


    // 密码找回
    function mail_certification_gbpwd($mail_to, $mail_content){
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", "LTAIAjLeruKbDb1l", "FJAlNoN7WK9tQx8GYDX7TMMROu5c45");
        $client = new \DefaultAcsClient($iClientProfile);
        $request = new SingleSendMailRequest();



        $request->setAccountName("mpubg@m.plgn.gamepp.com");
        $request->setFromAlias("绝地求生超级助手");
        $request->setAddressType(1);
        $request->setTagName("mailspubg");
        $request->setReplyToAddress("true");
        $request->setToAddress($mail_to);
        $request->setSubject("绝地求生超级助手用户系统");

        try {

            $mail_body = "尊敬的{$mail_to}：您好！</br>

                          绝地求生超级助手找回登录密码通知：
                          请点击下面链接找回您的登录密码：</br>
                          
                          <a href=''>{$mail_content}</a> </br>
                          
                          如果链接不能点击，请复制地址到浏览器，然后直接打开。</br>
                          
                          如果链接已经失效，请重新到游戏加加网站找回您的密码！谢谢您的合作！";
            $request->setHtmlBody($mail_body);
            $response = $client->getAcsResponse($request);

            return true;
            //echo "发送完成"."<br>";
            //print_r($response);
        }
        catch (ClientException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }
        catch (ServerException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }
    }

    function mail_certification_cemail($mail_to, $mail_content){
        $iClientProfile = \DefaultProfile::getProfile("cn-hangzhou", "LTAIAjLeruKbDb1l", "FJAlNoN7WK9tQx8GYDX7TMMROu5c45");
        $client = new \DefaultAcsClient($iClientProfile);
        $request = new SingleSendMailRequest();



        $request->setAccountName("mpubg@m.plgn.gamepp.com");
        $request->setFromAlias("绝地求生超级助手");
        $request->setAddressType(1);
        $request->setTagName("mailspubg");
        $request->setReplyToAddress("true");
        $request->setToAddress($mail_to);
        $request->setSubject("绝地求生超级助手用户系统");

        try {

            $mail_body = "尊敬的{$mail_to}：</br>

                          您好！您现在正在更改绝地求生超级助手用户系统的绑定邮箱，请点击下面链接进行修改：</br>
                          
                          <a href=''>{$mail_content}</a> </br>
                          
                          如果链接不能点击，请复制地址到浏览器，然后直接打开。</br>
                          
                          （这是一封自动产生的email，请勿回复。）";

            $request->setHtmlBody($mail_body);
            $response = $client->getAcsResponse($request);

            return true;
            //echo "发送完成"."<br>";
            //print_r($response);
        }
        catch (ClientException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }
        catch (ServerException  $e) {
            print_r($e->getErrorCode());
            print_r($e->getErrorMessage());
        }

    }

}

