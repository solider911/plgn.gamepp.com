<?php
/**
 *PHPer:liu
 *time:2018/1/11/011 10:31
 *motto:Buddha bless, never bug!
 */
namespace app\common;
class Curl {
  public function curl ($url){
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($ch, CURLOPT_URL, $url);
      $json =  curl_exec($ch);
      curl_close($ch);
      $arr=json_decode($json,1);
      return $arr;
  }
}
