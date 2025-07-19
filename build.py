import os
import subprocess

def run_build():
    # 清理旧构建
    if os.path.exists('build'):
        os.system('rd /s /q build')
    if os.path.exists('dist'):
        os.system('rd /s /q dist')
    
    # 打包命令
    cmd = [
        'pyinstaller',
        '--onefile',
        '--name', 'FileShareServer',
        '--add-data', 'templates;templates',
        '--add-data', 'install;install',
        '--noconsole',
        'app.py'
    ]
    
    subprocess.run(cmd)
    
    # 创建部署目录
    os.makedirs('dist/FileShareServer', exist_ok=True)
    os.system('copy dist\\FileShareServer.exe dist\\FileShareServer /Y')
    os.system('xcopy templates dist\\FileShareServer\\templates /E /I /Y')
    os.system('xcopy install dist\\FileShareServer\\install /E /I /Y')
    
    # 创建支持目录
    os.makedirs('dist/FileShareServer/downloads', exist_ok=True)
    os.makedirs('dist/FileShareServer/temp', exist_ok=True)
    
    # 创建启动脚本
    with open('dist/FileShareServer/start_server.bat', 'w') as f:
        f.write("@echo off\n")
        f.write("echo 正在启动文件共享服务器...\n")
        f.write("FileShareServer.exe\n")
        f.write("pause\n")
    
    print("构建完成！输出目录: dist\\FileShareServer")

if __name__ == '__main__':
    run_build()