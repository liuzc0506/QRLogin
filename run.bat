@echo off
setlocal enabledelayedexpansion

@REM REM 设置URL
set "url=%1"

@REM REM 启动mitmweb并将其进程ID保存到变量mitmweb_pid中
start mitmweb -s mitm.py --set url=!url! -p 7778 --mode upstream:http://localhost:7890
set "mitmweb_pid=!errorlevel!"

python selenium_qrcode.py !url!

@REM REM 结束mitmweb的运行
taskkill /F /PID !mitmweb_pid!