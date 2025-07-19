@echo off
REM ========================
REM Windows服务安装脚本
REM ========================

set SERVICE_NAME=FileShareService
set EXE_PATH=%~dp0FileShareServer.exe

echo 正在安装 %SERVICE_NAME% 服务...

REM 下载nssm
if not exist nssm.exe (
    echo 正在下载nssm...
    powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip' -OutFile 'nssm.zip'"
    powershell -Command "Expand-Archive -Path 'nssm.zip' -DestinationPath '.'"
    move nssm-2.24-101-g897c7ad\win64\nssm.exe .
    rmdir /s /q nssm-2.24-101-g897c7ad
    del nssm.zip
)

REM 安装服务
nssm install %SERVICE_NAME% "%EXE_PATH%"
nssm set %SERVICE_NAME% Description "文件共享服务器"
nssm set %SERVICE_NAME% AppDirectory "%~dp0"
nssm set %SERVICE_NAME% AppStdout "%~dp0service.log"
nssm set %SERVICE_NAME% AppStderr "%~dp0service_error.log"

echo 启动服务...
nssm start %SERVICE_NAME%

echo 安装完成！服务名称: %SERVICE_NAME%
echo 管理命令:
echo   nssm start %SERVICE_NAME%
echo   nssm stop %SERVICE_NAME%
echo   nssm restart %SERVICE_NAME%
echo   nssm remove %SERVICE_NAME%
pause