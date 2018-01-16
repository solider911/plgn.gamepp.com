#!/bin/bash

PHP_PATH="/usr/local/php/bin/php"

# origin log file
log_file_path="/www/log/nginx/access/plgn.gamepp.com.log"

# if target dir not exist, then mkdir
log_save_dir="/www/log/nginx/access/plgn.gamepp.com/`date +%Y-%m-%d`/"
if [ ! -d "$log_save_dir" ];then
    mkdir -p "$log_save_dir"
fi

# target filename
log_save_filename="hour_`date +%H`.log"

mv $log_file_path $log_save_dir$log_save_filename
cd /root/ && lnmp reload
gzip $log_save_dir$log_save_filename


#cd /alidata/www/plgn.gamepp.com/log/ && $PHP_PATH /alidata/www/plgn.gamepp.com/log/u005log_to_db.php

 
