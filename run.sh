#!/bin/bash


# url=https://kyfw.12306.cn/otn/resources/login.html
url=$1

# 后台运行mitmweb，并将其进程ID保存到变量mitmweb_pid中
mitmweb -s mitm.py --set url=$url -p 7778 --mode upstream:http://localhost:7890 &
mitmweb_pid=$!

/opt/homebrew/bin/python3 selenium_qrcode.py $url

# 当selenium_qrcode脚本执行完毕后，结束mitmweb的运行
kill -9 $mitmweb_pid
